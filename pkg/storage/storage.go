// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/hashicorp/go-multierror"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/lockmap"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/dummy"
	"github.com/jmoiron/sqlx"
)

type BlobStorage interface {
	io.Closer
	Get(ctx context.Context, key []byte) ([]byte, error)
	Replace(ctx context.Context, key []byte, blob []byte) error
	Delete(ctx context.Context, key []byte) error
}

// Storage is the implementation of firmware images storage (which handles
// both: metadata and the image itself).
type Storage struct {
	DB                       *sqlx.DB
	BlobStorage              BlobStorage
	Cache                    Cache
	CacheLockMap             *lockmap.LockMap
	Logger                   logger.Logger
	RetryDefaultInitialDelay time.Duration
	RetryTimeout             time.Duration

	insertTriesLimit uint
}

const (
	defaultRetryDefaultInitialDelay = time.Second
	defaultRetryTimeout             = 10 * time.Minute
)

// Cache is used to avoid repeating queries to the backends
type Cache interface {
	// Get returns an object, given its cache key.
	//
	// Returns an untyped nil if there is no such entry in the cache.
	Get(ctx context.Context, objectKey objhash.ObjHash) any

	// Set tries to set an object with its cache key. It is up to implementation
	// to decide whether to actually store the object.
	//
	// objectSize is only notifies the implementation (of Cache) about how
	// much memory the object consumes (rough estimation).
	Set(ctx context.Context, objectKey objhash.ObjHash, object any, objectSize uint64)
}

// NewStorage returns an instance of Storage.
func New(
	rdbmsDriver string,
	rdbmsDSN string,
	blobStorage BlobStorage,
	cache Cache,
	log logger.Logger,
) (*Storage, error) {
	if log == nil {
		log = dummy.New()
	}
	if cache == nil {
		cache = dummyCache{}
	}
	stor := &Storage{
		Logger:                   log,
		BlobStorage:              blobStorage,
		Cache:                    cache,
		CacheLockMap:             lockmap.NewLockMap(),
		RetryDefaultInitialDelay: defaultRetryDefaultInitialDelay,
		RetryTimeout:             defaultRetryTimeout,
		insertTriesLimit:         insertTriesLimit,
	}

	db, err := sql.Open(rdbmsDriver, rdbmsDSN)
	if err != nil {
		return nil, ErrInitMySQL{Err: err, DSN: rdbmsDSN}
	}

	err = db.Ping()
	if err != nil {
		return nil, ErrMySQLPing{Err: err}
	}

	stor.DB = sqlx.NewDb(db, "afas")
	return stor, nil
}

func (stor *Storage) startTransaction(
	ctx context.Context,
) (*sqlx.Tx, error) {
	return stor.DB.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
}

func (stor *Storage) startTransactionWithRollback(ctx context.Context) (*sqlx.Tx, context.CancelFunc, error) {
	tx, err := stor.startTransaction(ctx)
	if err != nil {
		return nil, nil, ErrSelect{Err: err}
	}

	return tx, func() {
		errRollback := tx.Rollback()
		if errRollback == nil {
			return
		}
		if errors.Is(errRollback, mysql.ErrInvalidConn) {
			// Lost connection, therefore the transaction will be reset
			// automatically.
			return
		}
		// To do not leave a transaction which could hang other workers we panic,
		// it with disconnect from MySQL and force-release the transaction.
		panic(fmt.Errorf("unable to commit the transaction and do not how to remediate: %w", errRollback))
	}, nil
}

// Close stops the instance of the Storage.
func (stor *Storage) Close() error {
	return multierror.Append((error)(nil),
		stor.DB.Close(),
		stor.BlobStorage.Close(),
	).ErrorOrNil()
}

func (stor *Storage) retryLoop(fn func() error) error {
	timeout := time.NewTimer(stor.RetryTimeout)
	defer timeout.Stop()

	delay := stor.RetryDefaultInitialDelay

	for {
		err := fn()
		if err == nil {
			return nil
		}
		stor.Logger.Debugf("err == %T:%v", err, err)

		select {
		case <-timeout.C:
			stor.Logger.Debugf("timed out")
			return err
		default:
		}

		canRetryErr, ok := err.(interface {
			CanRetry() bool
		})
		if !ok || !canRetryErr.CanRetry() {
			stor.Logger.Debugf("is not a retriable error")
			return err
		}
		if retryAter, ok := err.(interface {
			RetryAt() time.Time
		}); ok {
			retryAt := retryAter.RetryAt()
			delay = time.Now().Sub(retryAt)
		}

		stor.Logger.Debugf("delay is: %v", delay)
		select {
		case <-time.After(delay):
			delay *= 2
		case <-timeout.C:
			// It might be we waited a long time in this `select`, was it for
			// nothing? No: we will make one last try before exit (and will
			// exit in the `select` above).
		}
		stor.Logger.Debugf("retry")
	}
}

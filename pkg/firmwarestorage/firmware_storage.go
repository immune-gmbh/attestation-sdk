package firmwarestorage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
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
	Get(ctx context.Context, key string) ([]byte, error)
	Replace(ctx context.Context, key string, blob []byte) error
}

// Storage is the implementation of firmware images storage (which handles
// both: metadata and the image itself).
type FirmwareStorage struct {
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
	rdbmsURL string,
	blobStorage BlobStorage,
	cache Cache,
	log logger.Logger,
) (*FirmwareStorage, error) {
	if log == nil {
		log = dummy.New()
	}
	if cache == nil {
		cache = dummyCache{}
	}
	stor := &FirmwareStorage{
		Logger:                   log,
		BlobStorage:              blobStorage,
		Cache:                    cache,
		CacheLockMap:             lockmap.NewLockMap(),
		RetryDefaultInitialDelay: defaultRetryDefaultInitialDelay,
		RetryTimeout:             defaultRetryTimeout,
		insertTriesLimit:         insertTriesLimit,
	}

	parsedURL, err := url.Parse(rdbmsURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse URL '%s': %w", rdbmsURL, err)
	}

	if parsedURL.Scheme == "" {
		return nil, fmt.Errorf("RDBMS driver is not set")
	}

	dataSourceString := strings.SplitN(parsedURL.String(), "://", 2)[1]
	db, err := sql.Open(parsedURL.Scheme, dataSourceString)

	err = db.Ping()
	if err != nil {
		return nil, ErrMySQLPing{Err: err}
	}

	stor.DB = sqlx.NewDb(db, "afas")
	return stor, nil
}

func (fwStor *FirmwareStorage) startTransaction(
	ctx context.Context,
) (*sqlx.Tx, error) {
	return fwStor.DB.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
}

func (fwStor *FirmwareStorage) startTransactionWithRollback(ctx context.Context) (*sqlx.Tx, context.CancelFunc, error) {
	tx, err := fwStor.startTransaction(ctx)
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
func (fwStor *FirmwareStorage) Close() error {
	return multierror.Append((error)(nil),
		fwStor.DB.Close(),
		fwStor.BlobStorage.Close(),
	).ErrorOrNil()
}

func (fwStor *FirmwareStorage) retryLoop(fn func() error) error {
	timeout := time.NewTimer(fwStor.RetryTimeout)
	defer timeout.Stop()

	delay := fwStor.RetryDefaultInitialDelay

	for {
		err := fn()
		if err == nil {
			return nil
		}
		fwStor.Logger.Debugf("err == %T:%v", err, err)

		select {
		case <-timeout.C:
			fwStor.Logger.Debugf("timed out")
			return err
		default:
		}

		canRetryErr, ok := err.(interface {
			CanRetry() bool
		})
		if !ok || !canRetryErr.CanRetry() {
			fwStor.Logger.Debugf("is not a retriable error")
			return err
		}
		if retryAter, ok := err.(interface {
			RetryAt() time.Time
		}); ok {
			retryAt := retryAter.RetryAt()
			delay = time.Now().Sub(retryAt)
		}

		fwStor.Logger.Debugf("delay is: %v", delay)
		select {
		case <-time.After(delay):
			delay *= 2
		case <-timeout.C:
			// It might be we waited a long time in this `select`, was it for
			// nothing? No: we will make one last try before exit (and will
			// exit in the `select` above).
		}
		fwStor.Logger.Debugf("retry")
	}
}

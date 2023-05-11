package storage

import (
	"context"
	"database/sql"
	"time"

	"libfb/go/fbmysql"
	"manifold/blobstore/if/blobstore"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/lockmap"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/dummy"
	"github.com/jmoiron/sqlx"
)

// Storage is the implementation of firmware images storage (which handles
// both: metadata and the image itself).
type Storage struct {
	DB                       *sqlx.DB
	Manifold                 ManifoldClient
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

// ManifoldClient is an interface to abstract from *libfb/go/manifold.Client.
//
// Here's how to initialize an implementation of this interface:
//
// 	   manifoldOpts := manifold.DefaultOptions()
//	   manifoldOpts.APIKey = manifoldAPIKey
//	   manifoldOpts.Bucket = manifoldBucket
//	   manifoldClient, err := manifold.NewClient(manifoldOpts)
type ManifoldClient interface {
	Replace(path string, b []byte) (copied int64, err error)
	Download(path string) (b []byte, err error)
	Close() error
}

// Cache is used to avoid repeating queries to the backends
type Cache interface {
	// Get returns an object, given its cache key.
	//
	// Returns an untyped nil if there is no such entry in the cache.
	Get(ctx context.Context, objectKey objhash.ObjHash) any

	// Set tries to set an object with its cache key. It is up to implementation
	// to decide wheather to actually store the object.
	//
	// objectSize is only notifies the implementation (of Cache) about how
	// much memory the object consumes (rough estimation).
	Set(ctx context.Context, objectKey objhash.ObjHash, object any, objectSize uint64)
}

// NewStorage returns an instance of Storage.
func NewStorage(
	xdbTier string,
	manifold ManifoldClient,
	cache Cache,
	log logger.Logger,
) (*Storage, error) {
	var err error

	if log == nil {
		log = dummy.New()
	}
	if cache == nil {
		cache = dummyCache{}
	}
	stor := &Storage{
		Logger:                   log,
		Manifold:                 manifold,
		Cache:                    cache,
		CacheLockMap:             lockmap.NewLockMap(),
		RetryDefaultInitialDelay: defaultRetryDefaultInitialDelay,
		RetryTimeout:             defaultRetryTimeout,
		insertTriesLimit:         insertTriesLimit,
	}

	fbmysqlConfig := fbmysql.DefaultConfigRW(xdbTier)
	fbmysqlConfig.MySQLConfig.ParseTime = true

	// The whole data access design of package "storage" was written in assumption of isolation level "READ-COMMITTED",
	// and we do not set it then we get errors like this:
	// Error 1205: Lock wait timeout exceeded; try restarting transaction: Timeout on record in index: afas/analyze_report.processed_at
	fbmysqlConfig.MySQLConfig.Params = map[string]string{
		"transaction_isolation": "'READ-COMMITTED'",
	}

	mysqlConnector, err := fbmysql.NewConnector(fbmysqlConfig)
	if err != nil {
		return nil, ErrInitMySQL{Err: err}
	}

	db := sql.OpenDB(mysqlConnector)
	err = db.Ping()
	if err != nil {
		return nil, ErrMySQLPing{Err: err}
	}

	stor.DB = sqlx.NewDb(db, "afas")
	return stor, nil
}

// Close stops the instance of the Storage.
func (stor *Storage) Close() error {
	err := errors.MultiError{}
	err.Add(
		stor.DB.Close(),
		stor.Manifold.Close(),
	)
	return err.ReturnValue()
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

		blobstoreErr, ok := err.(*blobstore.StorageException)
		if !ok {
			stor.Logger.Debugf("unknown error type")
			return err
		}

		if !blobstoreErr.CanRetry {
			stor.Logger.Debugf("is not a retriable error")
			return err
		}

		if blobstoreErr.RetryAfterMsec != 0 {
			delay = time.Millisecond * time.Duration(blobstoreErr.RetryAfterMsec)
		}

		stor.Logger.Debugf("delay is: %v (%d)", delay, blobstoreErr.RetryAfterMsec)
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

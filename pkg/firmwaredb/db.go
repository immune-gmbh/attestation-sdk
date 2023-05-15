package rtpdb

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"

	"libfb/go/fbmysql"
)

const (
	// DefaultXDBTier is the tier of the XDB of the RTP firmware table
	DefaultXDBTier = `xdb.rtp_firmware`
)

// DB is the type representing RTP firmware table accessor.
type DB struct {
	Tier string
	DB   *sqlx.DB
	Role string
}

var _ RWAccess = (*DB)(nil)

// GetDBRO returns a read-only accessor to the RTP firmware table.
func GetDBRO() (*DB, error) {
	return GetDB(fbmysql.DefaultConfig(DefaultXDBTier))
}

// GetDBRW returns a read-write accessor to the RTP firmware table.
func GetDBRW() (*DB, error) {
	return GetDB(fbmysql.DefaultConfigRW(DefaultXDBTier))
}

// GetDB returns a configurable accessor to the RTP firmware table
func GetDB(config *fbmysql.Config) (*DB, error) {
	// TODO: Use FirmwarePortalV2 API instead of direct access through MySQL and NodeAPI.

	if config == nil {
		config = fbmysql.DefaultConfig(DefaultXDBTier)
	}

	mysqlConnector, err := fbmysql.NewConnector(config)
	if err != nil {
		return nil, ErrInitMySQL{Err: err}
	}

	db := sql.OpenDB(mysqlConnector)
	err = db.Ping()
	if err != nil {
		return nil, ErrMySQLPing{Err: err}
	}

	return &DB{
		Tier: config.Tier,
		DB:   sqlx.NewDb(db, "rtp_firmware"),
		Role: config.Role,
	}, nil
}

// ExecContext calls (*sql.DB).ExecContext
func (db *DB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return db.DB.ExecContext(ctx, query, args...)
}

// Query calls (*sql.DB).Query
func (db *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return db.DB.Query(query, args...)
}

// Queryx calls (*sqlx.DB).Queryx
func (db *DB) Queryx(query string, args ...interface{}) (*sqlx.Rows, error) {
	return db.DB.Queryx(query, args...)
}

// QueryRowx calls (*sqlx.DB).QueryRowx
func (db *DB) QueryRowx(query string, args ...interface{}) *sqlx.Row {
	return db.DB.QueryRowx(query, args...)
}

// QueryContext calls (*sql.DB).QueryContext
func (db *DB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return db.DB.QueryContext(ctx, query, args...)
}

// QueryxContext calls (*sqlx.DB).QueryxContext
func (db *DB) QueryxContext(ctx context.Context, query string, args ...interface{}) (*sqlx.Rows, error) {
	return db.DB.QueryxContext(ctx, query, args...)
}

// QueryRowxContext calls (*sqlx.DB).QueryRowxContext
func (db *DB) QueryRowxContext(ctx context.Context, query string, args ...interface{}) *sqlx.Row {
	return db.DB.QueryRowxContext(ctx, query, args...)
}

// Close implements io.Closer.
func (db *DB) Close() error {
	return db.DB.Close()
}

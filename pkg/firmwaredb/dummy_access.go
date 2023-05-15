package rtpdb

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
)

// DummyRWAccess is a dummy implementation of RWAccess
type DummyRWAccess struct {
	QueryFn            func(query string, args ...interface{}) (*sql.Rows, error)
	QueryxFn           func(query string, args ...interface{}) (*sqlx.Rows, error)
	QueryRowxFn        func(query string, args ...interface{}) *sqlx.Row
	ExecContextFn      func(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContextFn     func(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryxContextFn    func(ctx context.Context, query string, args ...interface{}) (*sqlx.Rows, error)
	QueryRowxContextFn func(ctx context.Context, query string, args ...interface{}) *sqlx.Row
}

var _ RWAccess = DummyRWAccess{}

// Query implements interface RWAccess
func (a DummyRWAccess) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return a.QueryFn(query, args...)
}

// Queryx implements interface RWAccess
func (a DummyRWAccess) Queryx(query string, args ...interface{}) (*sqlx.Rows, error) {
	return a.QueryxFn(query, args...)

}

// QueryRowx implements interface RWAccess
func (a DummyRWAccess) QueryRowx(query string, args ...interface{}) *sqlx.Row {
	return a.QueryRowxFn(query, args...)
}

// ExecContext implements interface RWAccess
func (a DummyRWAccess) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return a.ExecContextFn(ctx, query, args...)
}

// QueryContext implements interface RWAccess
func (a DummyRWAccess) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return a.QueryContextFn(ctx, query, args...)
}

// QueryxContext implements interface RWAccess
func (a DummyRWAccess) QueryxContext(ctx context.Context, query string, args ...interface{}) (*sqlx.Rows, error) {
	return a.QueryxContextFn(ctx, query, args...)
}

// QueryRowxContext implements interface RWAccess
func (a DummyRWAccess) QueryRowxContext(ctx context.Context, query string, args ...interface{}) *sqlx.Row {
	return a.QueryRowxContextFn(ctx, query, args...)
}

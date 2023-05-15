package rtpdb

import (
	"github.com/jmoiron/sqlx"
)

// Querier is an interface of an accessor to RTP firmware table
type Querier interface {
	sqlx.Queryer
	sqlx.QueryerContext
}

// RWAccess provides a read-write access to RTP firmware table
type RWAccess interface {
	Querier
	sqlx.ExecerContext
}

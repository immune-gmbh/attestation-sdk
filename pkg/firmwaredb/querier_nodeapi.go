//go:build rtpdb_nodeapi
// +build rtpdb_nodeapi

package rtpdb

// RWAccessWithNodeAPI provides a read-write access to RTP firmware table,
// with NodeAPI-based extensions.
type RWAccessWithNodeAPI interface {
	Querier
	sqlx.ExecerContext
	Add(Firmware) (fbid int64, err error)
}

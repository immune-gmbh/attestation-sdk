//go:build rtpdb_nodeapi
// +build rtpdb_nodeapi

package rtpdb

import (
	"context"
)

// AddFirmware create a new entry with the defined firmware info and returns the resulting FBID
// of the entry.
func AddFirmware(ctx context.Context, db RWAccessWithNodeAPI, firmwareMeta Firmware) (fbid int64, err error) {
	return db.Add(firmwareMeta)
}

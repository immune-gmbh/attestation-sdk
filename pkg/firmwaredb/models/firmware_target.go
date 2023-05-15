package models

// FirmwareTarget represent a row of table containing connections
// information where a firmware should be applied
type FirmwareTarget struct {
	ID         int64   `db:"id,pk"`
	FirmwareID int64   `db:"firmware_id"`
	ModelID    *int64  `db:"model_id"`
	Hostname   *string `db:"hostname"`
}

package models

// Firmware represent a row of table containing metadata
// about firmware images.
type Firmware struct {
	ID       int64        `db:"id,pk"`
	Type     FirmwareType `db:"type"`
	Version  string       `db:"version"`
	ImageURL string       `db:"image_url"`
}

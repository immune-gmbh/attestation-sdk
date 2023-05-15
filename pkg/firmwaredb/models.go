package firmwaredb

import "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb/models"

// FirmwareType represents description of firmware type values
type FirmwareType = models.FirmwareType

const (
	// BiosFirmwareType represents BIOS
	FirmwareTypeBIOS = models.FirmwareTypeBIOS
)

// Firmware represent a row of table containing metadata
// about firmware images.
type Firmware = models.Firmware

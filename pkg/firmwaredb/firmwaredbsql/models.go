package firmwaredbsql

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb/models"
)

// FirmwareType represents description of firmware type values
type FirmwareType = models.FirmwareType

const (
	// BiosFirmwareType represents BIOS
	FirmwareTypeBIOS = models.FirmwareTypeBIOS
)

// Firmware represent a row of table containing metadata
// about firmware images.
type Firmware = models.Firmware

type FirmwareTarget = models.FirmwareTarget
type FirmwareMeasurement = models.FirmwareMeasurement
type FirmwareMeasurementType = models.FirmwareMeasurementType
type FirmwareMeasurementMetadata = models.FirmwareMeasurementMetadata

type Filter = firmwaredb.Filter
type Filters = firmwaredb.Filters

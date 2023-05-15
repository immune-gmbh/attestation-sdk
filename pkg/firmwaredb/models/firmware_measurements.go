package models

import "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"

// Relations:
//
// Target <- FirmwareTarget -> Firmware <- FirmwareMeasurement -> FirmwareMeasurementType <- FirmwareMeasurementMetadata

type FirmwareMeasurementType struct {
	ID          int64  `db:"id,pk"`
	Name        string `db:"name"`
	Description string `db:"description"`

	// loaded from other tables
	Metadata []*FirmwareMeasurementMetadata
}

type FirmwareMeasurementMetadata struct {
	ID                int64  `db:"id,pk"`
	MeasurementTypeID int64  `db:"type_id"`
	Key               string `db:"key"`
	Value             string `db:"value"`

	// loaded from other tables
	FirmwareMeasurementType *FirmwareMeasurementType
}

type FirmwareMeasurement struct {
	ID                int64                `db:"id,pk"`
	FirmwareID        int64                `db:"firmware_id"`
	MeasurementTypeID int64                `db:"type_id"`
	Value             types.ConvertedBytes `db:"value"`

	// loaded from other tables
	Firmware                *Firmware
	FirmwareMeasurementType *FirmwareMeasurementType
}

package models

import (
	"database/sql/driver"
	"fmt"
)

type FirmwareType uint

const (
	FirmwareTypeUndefined = FirmwareType(iota)
	FirmwareTypeBIOS

	EndOfFirmwareType
)

func (t FirmwareType) String() string {
	switch t {
	case FirmwareTypeUndefined:
		return "NULL"
	case FirmwareTypeBIOS:
		return "BIOS"
	default:
		return fmt.Sprintf("unknown_type_%d", uint(t))
	}
}

// Value converts the value to be stored in DB.
func (t FirmwareType) Value() (driver.Value, error) {
	if t <= FirmwareTypeUndefined || t >= EndOfFirmwareType {
		return nil, fmt.Errorf("unexpected value: %s", t.String())
	}

	return t.String(), nil
}

// Scan converts DB's a value to the FirmwareType.
func (t *FirmwareType) Scan(srcI interface{}) error {
	srcB, ok := srcI.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, received %T", srcI)
	}
	src := string(srcB)

	for candidate := FirmwareTypeUndefined + 1; candidate < EndOfFirmwareType; candidate++ {
		if src == candidate.String() {
			*t = candidate
			return nil
		}
	}

	return fmt.Errorf("unknown firmware type: '%s'", src)
}

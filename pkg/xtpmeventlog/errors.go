package xtpmeventlog

import (
	"fmt"
)

// ErrNoPCR0DATALog means there is no log entry, corresponding to PCR0_DATA
// measurement.
type ErrNoPCR0DATALog struct{}

// Error implements interface "error".
func (err ErrNoPCR0DATALog) Error() string {
	return fmt.Sprintf("no PCR0_DATA log entry")
}

// ErrPCR0DataLogTooSmall means found log entry has too small data which
// does not contain the original data of pcr.Measurement is a known format.
//
// It might mean that the firmware does not support this extension.
type ErrPCR0DataLogTooSmall struct {
	Data []byte
}

// Error implements interface "error".
func (err ErrPCR0DataLogTooSmall) Error() string {
	return fmt.Sprintf("PCR0_DATA log entry data is too small")
}

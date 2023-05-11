package errors

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase/validator"

	"github.com/linuxboot/fiano/pkg/guid"
)

// ErrValidationInfo is an error. See the description in method Error.
type ErrValidationInfo struct {
	Err  error
	Path string
}

// Error implements error.
func (err ErrValidationInfo) Error() string {
	return fmt.Sprintf("unable to get information for validation: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrValidationInfo) Unwrap() error {
	return err.Err
}

// ErrModify is an error. See the description in method Error.
type ErrModify struct {
	Err error
}

// Error implements error.
func (err ErrModify) Error() string {
	return fmt.Sprintf("unable to modify the firmware: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrModify) Unwrap() error {
	return err.Err
}

// ErrOrigFirmware is an error. See the description in method Error.
type ErrOrigFirmware = validator.ErrOrigFirmware

// ErrParseFirmware is an error. See the description in method Error.
type ErrParseFirmware = validator.ErrParseFirmware

// ErrLookupGUID is an error. See the description in method Error.
type ErrLookupGUID struct {
	Err  error
	GUID guid.GUID
}

// Error implements error.
func (err ErrLookupGUID) Error() string {
	return fmt.Sprintf("unable to lookup for UEFI GUID '%s': %v", err.GUID, err.Err)
}

// ErrUnexpectedGUIDCount is an error. See the description in method Error.
type ErrUnexpectedGUIDCount struct {
	GUID     guid.GUID
	Actual   int
	Expected int
}

// Error implements error.
func (err ErrUnexpectedGUIDCount) Error() string {
	return fmt.Sprintf("found unexpected amount of UEFI nodes of GUID %s: actual:%d expected:%d",
		err.GUID, err.Actual, err.Expected)
}

// ErrPaddingNotFound is an error. See the description in method Error.
type ErrPaddingNotFound struct{}

// Error implements error.
func (err ErrPaddingNotFound) Error() string {
	return "padding not found"
}

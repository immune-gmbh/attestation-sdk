// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package errors

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/validator"

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

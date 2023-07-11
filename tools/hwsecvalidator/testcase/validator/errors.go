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
package validator

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"

	"github.com/immune-gmbh/attestation-sdk/pkg/xtpmeventlog"
)

// ErrSetup is an error. See the description in method Error.
type ErrSetup struct {
	Err error
}

// Error implements error.
func (err ErrSetup) Error() string {
	return fmt.Sprintf("unable to prepare the test case: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrSetup) Unwrap() error {
	return err.Err
}

// ErrExpectedFirmware is an error. See the description in method Error.
type ErrExpectedFirmware struct {
	Err error
}

// Error implements error.
func (err ErrExpectedFirmware) Error() string {
	return fmt.Sprintf("unable to confirm the machine has the expected firmware: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrExpectedFirmware) Unwrap() error {
	return err.Err
}

// ErrExpectedPCR0 is an error. See the description in method Error.
type ErrExpectedPCR0 struct {
	ErrPCR0Mismatch

	ExpectedMeasurementsLog string
}

// Error implements error.
func (err ErrExpectedPCR0) Error() string {
	return fmt.Sprintf(
		`PCR0 extracted from TPM (%X) does match the expected one (%X)`,
		err.ErrPCR0Mismatch.Received,
		err.ErrPCR0Mismatch.Expected,
	)
}

// Description implements Descriptioner.
func (err ErrExpectedPCR0) Description() string {
	return fmt.Sprintf(
		"PCR0 extracted from TPM (%X) does match the expected one (%X).\n\nThe chain of expected measurements:\n\n%s",
		err.ErrPCR0Mismatch.Received,
		err.ErrPCR0Mismatch.Expected,
		err.ExpectedMeasurementsLog,
	)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrExpectedPCR0) Unwrap() error {
	return err.ErrPCR0Mismatch
}

// ErrDump is an error. See the description in method Error.
type ErrDump struct {
	Err error
}

// Error implements error.
func (err ErrDump) Error() string {
	return fmt.Sprintf("unable to dump the firmware image: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrDump) Unwrap() error {
	return err.Err
}

// Description explains how to interpret the error in details.
func (err ErrDump) Description() string {
	return fmt.Sprintf(`It was unable to dump current firmware image.
The reported error is: %v

Try to repeat it with command:
    flashrom -p internal:laptop=this_is_not_a_laptop,ich_spi_mode=hwseq --ifd -i bios -r /tmp/firmware.fd

If it does not work then try to dump using afulnx tool. If you were able to dump firmware using flashrom
or/and afulnx then it is an internal error of the testing tool. If you were not able to then the host
is malfunctioning.`, err.Err)
}

// ErrIncorrectEventLog is an error. See the description in method Error.
type ErrIncorrectEventLog struct {
	Err error
}

// Error implements error.
func (err ErrIncorrectEventLog) Error() string {
	return fmt.Sprintf("invalid EventLog: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrIncorrectEventLog) Unwrap() error {
	return err.Err
}

// ErrCurrentFirmware is an error. See the description in method Error.
type ErrCurrentFirmware struct {
	Err error
}

// Error implements error.
func (err ErrCurrentFirmware) Error() string {
	return fmt.Sprintf("current firmware: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrCurrentFirmware) Unwrap() error {
	return err.Err
}

// ErrOrigFirmware is an error. See the description in method Error.
type ErrOrigFirmware struct {
	Err error
}

// Error implements error.
func (err ErrOrigFirmware) Error() string {
	return fmt.Sprintf("original firmware: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrOrigFirmware) Unwrap() error {
	return err.Err
}

// ErrParseFirmware is an error. See the description in method Error.
type ErrParseFirmware struct {
	Err error
}

// Error implements error.
func (err ErrParseFirmware) Error() string {
	return fmt.Sprintf("unable to parse firmware: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrParseFirmware) Unwrap() error {
	return err.Err
}

// ErrParseDMITable is an error. See the description in method Error.
type ErrParseDMITable struct {
	Err error
}

// Error implements error.
func (err ErrParseDMITable) Error() string {
	return fmt.Sprintf("unable to parse DMI table: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrParseDMITable) Unwrap() error {
	return err.Err
}

// ErrLocalDMITable is an error. See the description in method Error.
type ErrLocalDMITable struct {
	Err error
}

func (err ErrLocalDMITable) Error() string {
	return fmt.Sprintf("unable to get local DMI table: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrLocalDMITable) Unwrap() error {
	return err.Err
}

// ErrStatusRegisters is an error. See the description in method Error.
type ErrStatusRegisters struct {
	Err error
}

// Error implements error.
func (err ErrStatusRegisters) Error() string {
	return fmt.Sprintf("unable to get status registers: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrStatusRegisters) Unwrap() error {
	return err.Err
}

// ErrFetchTXTConfigSpace is an error. See the description in method Error.
type ErrFetchTXTConfigSpace struct {
	Err error
}

// Error implements error.
func (err ErrFetchTXTConfigSpace) Error() string {
	return fmt.Sprintf("unable to fetch TXT config space: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrFetchTXTConfigSpace) Unwrap() error {
	return err.Err
}

// ErrReadTXTRegisters is an error. See the description in method Error.
type ErrReadTXTRegisters struct {
	Err error
}

// Error implements error.
func (err ErrReadTXTRegisters) Error() string {
	return fmt.Sprintf("unable to read TXT config space: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrReadTXTRegisters) Unwrap() error {
	return err.Err
}

// ErrReadMSRRegisters is an error. See the description in method Error.
type ErrReadMSRRegisters struct {
	Err error
}

// Error implements error.
func (err ErrReadMSRRegisters) Error() string {
	return fmt.Sprintf("unable to read MSR registers: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrReadMSRRegisters) Unwrap() error {
	return err.Err
}

// ErrGetPCR0Measurements is an error. See the description in method Error.
type ErrGetPCR0Measurements struct {
	Err error
}

// Error implements error.
func (err ErrGetPCR0Measurements) Error() string {
	return fmt.Sprintf("unable to get PCR0 measurements: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrGetPCR0Measurements) Unwrap() error {
	return err.Err
}

// ErrEventLog is an error. See the description in method Error.
type ErrEventLog struct {
	Err  error
	Path string
}

// Error implements error.
func (err ErrEventLog) Error() string {
	return fmt.Sprintf("unable to get EventLog by path '%s': %v", err.Path, err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrEventLog) Unwrap() error {
	return err.Err
}

// ErrAlg is an error. See the description in method Error.
type ErrAlg struct {
	Err error
	Alg tpm2.Algorithm
}

// Error implements error.
func (err ErrAlg) Error() string {
	return fmt.Sprintf("invalid algorithm %d: %v", err.Alg, err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrAlg) Unwrap() error {
	return err.Err
}

// ErrPCR0Mismatch is an error. See the description in method Error.
type ErrPCR0Mismatch struct {
	Received []byte
	Expected []byte
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrPCR0Mismatch) Error() string {
	return fmt.Sprintf("PCR0 mismatch: expected:%X received:%X", err.Expected, err.Received)
}

// ErrValidator is an error. See the description in method Error.
type ErrValidator struct {
	Err       error
	Validator Validator
}

// Error implements error.
func (err ErrValidator) Error() string {
	return fmt.Sprintf("validator %T returned error: %v", err.Validator, err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrValidator) Unwrap() error {
	return err.Err
}

// ErrTPM is an error. See the description in method Error.
type ErrTPM struct {
	Err error
}

// Error implements error.
func (err ErrTPM) Error() string {
	return fmt.Sprintf("TPM error: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrTPM) Unwrap() error {
	return err.Err
}

// ErrReplayEventLog is an error. See the description in method Error.
type ErrReplayEventLog struct {
	Err             error
	Algo            tpm2.Algorithm
	ReplayLog       string
	MeasurementsLog string
}

// Error implements error.
func (err ErrReplayEventLog) Error() string {
	return fmt.Sprintf("EventLog replay error: %v", err.Err)
}

// Description implements Descriptioner.
func (err ErrReplayEventLog) Description() string {
	var description strings.Builder

	switch subErr := err.Err.(type) {
	case ErrPCR0Mismatch:
		description.WriteString(fmt.Sprintf(`final PCR0 value (see tpm2_pcrread) %X does not match PCR0 value replayed from TPM EventLog: %X`,
			subErr.Expected,
			subErr.Received,
		))
	default:
		description.WriteString(fmt.Sprintf("unable to replay EventLog due to error: %v", err.Err))
	}

	if err.ReplayLog != "" {
		description.WriteString(fmt.Sprintf("\n\n== TPM EventLog replay ==\n%s", err.ReplayLog))
	}

	if err.MeasurementsLog != "" {
		description.WriteString(fmt.Sprintf("\n\n== Real Measurements ==\n%s", err.MeasurementsLog))
	}

	return description.String()
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrReplayEventLog) Unwrap() error {
	return err.Err
}

// ErrKMIDMismatch means KMID from ACM_POLICY_STATUS does not match the KMID
// from the Key Manifest.
type ErrKMIDMismatch struct {
	Actual   uint8
	Expected uint8
}

// Error implements error.
func (err ErrKMIDMismatch) Error() string {
	return fmt.Sprintf("key manifest ID (KMID) does not match: expected:%d != actual:%d",
		err.Expected, err.Actual)
}

// ErrAlignFirmwares means it was unable to align firmware images to each other
// to use the same PCR measurements offsets.
type ErrAlignFirmwares struct {
	Err error
}

// Error implements error.
func (err ErrAlignFirmwares) Error() string {
	return fmt.Sprintf("unable to align images: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrAlignFirmwares) Unwrap() error {
	return err.Err
}

// ErrWrongPCR0DATALog is an error. See the description in method Error.
type ErrWrongPCR0DATALog struct {
	Algo   tpm2.Algorithm
	Logged *xtpmeventlog.PCR0DATALog
	Err    error
}

// Error implements error.
func (err ErrWrongPCR0DATALog) Error() string {
	return fmt.Sprintf("the PCR0_DATA description in the EventLog is invalid: %v", err.Err)
}

// Description implements Descriptioner.
func (err ErrWrongPCR0DATALog) Description() string {
	var description strings.Builder
	description.WriteString(err.Error())
	description.WriteString(fmt.Sprintf("\nParsed PCR0_DATA EventLog: %#+v", err.Logged))
	return description.String()
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrWrongPCR0DATALog) Unwrap() error {
	return err.Err
}

// ErrCompilePCR0DATAMeasurement is an error. See the description in method Error.
type ErrCompilePCR0DATAMeasurement struct {
	PCR0Data *xtpmeventlog.PCR0DATALog
	HashAlgo tpm2.Algorithm
	Err      error
}

// Error implements error.
func (err ErrCompilePCR0DATAMeasurement) Error() string {
	return fmt.Sprintf("unable to compile PCR0_DATA log entry %#+v into a measurement for algo %v: %v",
		err.PCR0Data, err.HashAlgo, err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrCompilePCR0DATAMeasurement) Unwrap() error {
	return err.Err
}

// ErrReconstructDigestMismatch is an error. See the description in method Error.
type ErrReconstructDigestMismatch struct {
	PCR0Data *xtpmeventlog.PCR0DATALog
	HashAlgo tpm2.Algorithm
	Expected []byte
	Actual   []byte
}

// Error implements error.
func (err ErrReconstructDigestMismatch) Error() string {
	return fmt.Sprintf("digest reconstructed from PCR0_DATA extended EventLog data (%#+v) does not match the logged digest (in the EventLog) for algo %v: expected:%X, actual:%X",
		err.PCR0Data, err.HashAlgo, err.Expected, err.Actual)
}

// ErrOriginalPCR0 is an error. See the description in method Error.
type ErrOriginalPCR0 struct {
	PCR0Data *xtpmeventlog.PCR0DATALog
	HashAlgo tpm2.Algorithm
	Expected []byte
	Actual   []byte
}

// Error implements error.
func (err ErrOriginalPCR0) Error() string {
	return fmt.Sprintf("in the extended EventLog entry of PCR0_DATA (%#+v): the \"original PCR0\" (which is just after PCR0_DATA measurement) does not match the expected value for algo %v: expected:%X, actual:%X",
		err.PCR0Data, err.HashAlgo, err.Expected, err.Actual)
}

// ErrParsePCR0DATALog means the PCR0_DATA description in the EventLog is not parsable,
// by xtpmeventlog package.
type ErrParsePCR0DATALog struct {
	Err error
}

// Error implements error.
func (err ErrParsePCR0DATALog) Error() string {
	return fmt.Sprintf("unable to parse the PCR0_DATA description in the EventLog: %v", err.Err)
}

// Unwrap is a standard method used by package "errors" to handle nested
// errors.
func (err ErrParsePCR0DATALog) Unwrap() error {
	return err.Err
}

// ErrHostBootedUp means that the host booted up, but it wasn't expected to do so.
type ErrHostBootedUp struct {
}

func (err ErrHostBootedUp) Error() string {
	return "The host successfully booted up, but it wasn't expected to boot up"
}

// ErrHostFailedBootUp means that the host failed to boot up
type ErrHostFailedBootUp struct {
}

func (err ErrHostFailedBootUp) Error() string {
	return "The host failed to boot up"
}

// ErrSELNotFound means that no matching SEL event was found
type ErrSELNotFound struct {
	matchExpression string
}

func (err ErrSELNotFound) Error() string {
	return fmt.Sprintf("SEL event matching '%s' was not found", err.matchExpression)
}

// ErrUnexepectedSELFound means that a SEL event was found that should not be generated
type ErrUnexepectedSELFound struct {
	matchExpression string
}

func (err ErrUnexepectedSELFound) Error() string {
	return fmt.Sprintf("SEL event matching '%s' was found", err.matchExpression)
}

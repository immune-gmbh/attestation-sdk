package firmwarewand

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

type ErrInitFirmwareAnalyzer struct {
	Err error
}

func (err ErrInitFirmwareAnalyzer) Error() string {
	return fmt.Sprintf("unable to initialize a client to the firmware analyzer service: %v", err.Err)
}

func (err ErrInitFirmwareAnalyzer) Unwrap() error {
	return err.Err
}

func (err ErrInitFirmwareAnalyzer) ExitCode() int {
	return 5
}

type ErrDetectHostname struct {
	Err error
}

func (err ErrDetectHostname) Error() string {
	return fmt.Sprintf("unable to detect the hostname of the local machine: %v", err.Err)
}

func (err ErrDetectHostname) Unwrap() error {
	return err.Err
}

func (err ErrDetectHostname) ExitCode() int {
	return 6
}

type ErrGetFirmwareSize struct {
	Err error
}

func (err ErrGetFirmwareSize) Error() string {
	return fmt.Sprintf("unable to get size of a firmware: %v", err.Err)
}

func (err ErrGetFirmwareSize) Unwrap() error {
	return err.Err
}

func (err ErrGetFirmwareSize) ExitCode() int {
	return 7
}

type ErrBIOSInfo struct {
	Err error
}

func (err ErrBIOSInfo) Error() string {
	return fmt.Sprintf("unable to get information about BIOS: %v", err.Err)
}

func (err ErrBIOSInfo) Unwrap() error {
	return err.Err
}

func (err ErrBIOSInfo) ExitCode() int {
	return 8
}

type ErrSystemInfo struct {
	Err error
}

func (err ErrSystemInfo) Error() string {
	return fmt.Sprintf("unable to get information about the system: %v", err.Err)
}

func (err ErrSystemInfo) Unwrap() error {
	return err.Err
}

func (err ErrSystemInfo) ExitCode() int {
	return 9
}

type ErrDumpFirmware struct {
	Err error
}

func (err ErrDumpFirmware) Error() string {
	return fmt.Sprintf("unable to dump a firmware image: %v", err.Err)
}

func (err ErrDumpFirmware) Unwrap() error {
	return err.Err
}

func (err ErrDumpFirmware) ExitCode() int {
	return 9
}

type ErrCheckFirmware struct {
	Err error
}

func (err ErrCheckFirmware) Error() string {
	return fmt.Sprintf("unable to check the firmware image: %v", err.Err)
}

func (err ErrCheckFirmware) Unwrap() error {
	return err.Err
}

func (err ErrCheckFirmware) ExitCode() int {
	return 10
}

func jobIDString(b []byte) string {
	jobID, err := types.ParseJobID(fmt.Sprintf("%X", b))
	if err != nil {
		return "<none>"
	}
	return jobID.String()
}

// ErrUnableToGetDiffReport is returned when DiffFirmware returned a report
// without a DiffReport.
type ErrUnableToGetDiffReport struct {
	Err string
}

func (err ErrUnableToGetDiffReport) Error() string {
	return fmt.Sprintf("unable to get diff report: %v", err.Err)
}

// ErrCompress means a problem while compressing a firmware image.
type ErrCompress struct {
	Err error
}

func (err ErrCompress) Error() string {
	return fmt.Sprintf("unable to compress the firmware image: %v", err.Err)
}

func (err ErrCompress) Unwrap() error {
	return err.Err
}

// ErrInvalidInput means some function is used incorrectly (invalid input
// arguments).
type ErrInvalidInput struct {
	Desc string
}

func (err ErrInvalidInput) Error() string {
	return fmt.Sprintf("invalid input: %s", err.Desc)
}

// ErrFirmwareRequest means there was an issue when creating a DiffFirmware request
// object
type ErrFirmwareRequest struct {
	Err error
}

func (err ErrFirmwareRequest) Error() string {
	return fmt.Sprintf("unable to create DiffFirmwareRequest for firmware analyzer service: %v", err.Err)
}

func (err ErrFirmwareRequest) Unwrap() error {
	return err.Err
}

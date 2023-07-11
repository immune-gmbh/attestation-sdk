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
package controller

// TODO: move to package `errors`

import (
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/pkg/server/controller/helpers"
)

type ErrNoOrigImageToCompareWith = helpers.ErrNoOrigImageToCompareWith

// ErrInitStorage implements "error", for the description see Error.
type ErrInitStorage struct {
	Err error
}

func (err ErrInitStorage) Error() string {
	return fmt.Sprintf("unable to initialize image storage: %v", err.Err)
}

func (err ErrInitStorage) Unwrap() error {
	return err.Err
}

// ErrParseFirmware implements "error", for the description see Error.
type ErrParseFirmware struct {
	Err error
}

func (err ErrParseFirmware) Error() string {
	return fmt.Sprintf("unable to parse firmware: %v", err.Err)
}

func (err ErrParseFirmware) Unwrap() error {
	return err.Err
}

// ErrGetFirmwarePair implements "error", for the description see Error.
type ErrGetFirmwarePair struct {
	Err error
}

func (err ErrGetFirmwarePair) Error() string {
	return fmt.Sprintf("unable to get the firmwares pair (original + received): %v", err.Err)
}

func (err ErrGetFirmwarePair) Unwrap() error {
	return err.Err
}

// ErrDecompressReceived implements "error", for the description see Error.
type ErrDecompressReceived struct {
	Err error
}

func (err ErrDecompressReceived) Error() string {
	return fmt.Sprintf("unable to decompress the received image: %v", err.Err)
}

func (err ErrDecompressReceived) Unwrap() error {
	return err.Err
}

// ErrInitCache implements "error", for the description see Error.
type ErrInitCache struct {
	// For describes the purpose of the cache, which initialization have failed.
	For string

	// Err is the initialization error
	Err error
}

func (err ErrInitCache) Error() string {
	return fmt.Sprintf("unable to init cache for '%s': %v", err.For, err.Err)
}

func (err ErrInitCache) Unwrap() error {
	return err.Err
}

// ErrGetTagStore implements "error", for the description see Error.
type ErrGetTagStore struct {
	// Err is the initialization error
	Err error
}

func (err ErrGetTagStore) Error() string {
	return fmt.Sprintf("unable to get tag storage: %v", err.Err)
}

func (err ErrGetTagStore) Unwrap() error {
	return err.Err
}

// ErrInitDataCalculator implements "error", for the description see Error.
type ErrInitDataCalculator struct {
	// Err is the initialization error
	Err error
}

func (err ErrInitDataCalculator) Error() string {
	return fmt.Sprintf("unable to initialize data calculator: %v", err.Err)
}

func (err ErrInitDataCalculator) Unwrap() error {
	return err.Err
}

// ErrInitAnalysisExecutor implements "error", for the description see Error.
type ErrInitAnalysisExecutor struct {
	// Err is the initialization error
	Err error
}

func (err ErrInitAnalysisExecutor) Error() string {
	return fmt.Sprintf("unable to initialize analysis executor: %v", err.Err)
}

func (err ErrInitAnalysisExecutor) Unwrap() error {
	return err.Err
}

// ErrParseReceivedFirmware implements "error", for the description see Error.
type ErrParseReceivedFirmware struct {
	Err error
}

func (err ErrParseReceivedFirmware) Error() string {
	return fmt.Sprintf("unable to parse the  firmware to be checked: %v", err.Err)
}

func (err ErrParseReceivedFirmware) Unwrap() error {
	return err.Err
}

// ErrFetchOrigFirmware implements "error", for the description see Error.
type ErrFetchOrigFirmware struct {
	Version string
	Err     error
}

func (err ErrFetchOrigFirmware) Error() string {
	return fmt.Sprintf("unable to fetch the original firmware: %v", err.Err)
}

func (err ErrFetchOrigFirmware) Unwrap() error {
	return err.Err
}

// ThriftException converts the error into a thrift format
func (err ErrFetchOrigFirmware) ThriftException() error {
	return &afas.UnableToGetOriginalFirmware{
		Version: err.Version,
		Reason:  err.Error(),
	}
}

// NewErrFetchOrigFirmware creates a new ErrFetchOrigFirmware object
func NewErrFetchOrigFirmware(biosVersion string, err error) ErrFetchOrigFirmware {
	return ErrFetchOrigFirmware{
		Version: biosVersion,
		Err:     err,
	}
}

// ErrParseOrigFirmware implements "error", for the description see Error.
type ErrParseOrigFirmware struct {
	Version string
	Err     error
}

func (err ErrParseOrigFirmware) Error() string {
	return fmt.Sprintf("unable to parse the original firmware: %v", err.Err)
}

func (err ErrParseOrigFirmware) Unwrap() error {
	return err.Err
}

// ThriftException converts a Go err type into a Thrift Exception type
func (err ErrParseOrigFirmware) ThriftException() error {
	return &afas.UnableToGetOriginalFirmware{
		Version: err.Version,
		Reason:  err.Error(),
	}
}

// NewErrParseOrigFirmware creates a new ErrParseOrigFirmware  object
func NewErrParseOrigFirmware(version string, err error) ErrParseOrigFirmware {
	return ErrParseOrigFirmware{
		Version: version,
		Err:     err,
	}
}

// ErrInvalidHostConfiguration describes a situation when host configuration is invalid
// For example due to broken registers
type ErrInvalidHostConfiguration struct {
	Err error
}

func (err ErrInvalidHostConfiguration) Error() string {
	return fmt.Sprintf("invalid host configuration: %v", err.Err)
}

func (err ErrInvalidHostConfiguration) Unwrap() error {
	return err.Err
}

// ThriftException converts a Go err type into a Thrift Exception type
func (err ErrInvalidHostConfiguration) ThriftException() error {
	return &afas.IncorrectHostConfiguration{
		Reason: err.Error(),
	}
}

// NewErrInvalidHostConfiguration creates a new ErrInvalidHostConfiguration object
func NewErrInvalidHostConfiguration(err error) ErrInvalidHostConfiguration {
	return ErrInvalidHostConfiguration{Err: err}
}

// ErrUnableToGetDiffReport is returned when it was unable to get
// a diff report for selected images.
type ErrUnableToGetDiffReport struct {
	Err error
}

func (err ErrUnableToGetDiffReport) Error() string {
	return fmt.Sprintf("unable to get a diff report: %v", err.Err)
}

func (err ErrUnableToGetDiffReport) Unwrap() error {
	return err.Err
}

// ErrNoImage is a generic error to specify a case, where an action could
// not be performed, because no image was specified.
type ErrNoImage struct{}

func (err ErrNoImage) Error() string {
	return "no image"
}

// ErrInvalidImageID means the provided image ID could not be used, for
// example there is no image with such ID in BlobStorage.
type ErrInvalidImageID struct {
	Err error
}

func (err ErrInvalidImageID) Error() string {
	return fmt.Sprintf("invalid image ID: %v", err.Err)
}

func (err ErrInvalidImageID) Unwrap() error {
	return err.Err
}

// ErrInvalidDataSource means the provided DataSource value is not supported.
type ErrInvalidDataSource struct{}

func (err ErrInvalidDataSource) Error() string {
	return "invalid data source value"
}

// ErrInvalidMeasurementFlow means input PCR measurements flow is unknown.
type ErrInvalidMeasurementFlow struct {
	Err error
}

func (err ErrInvalidMeasurementFlow) Error() string {
	return fmt.Sprintf("invalid PCR measurements flow: %v", err.Err)
}

func (err ErrInvalidMeasurementFlow) Unwrap() error {
	return err.Err
}

// ErrInvalidTPMType means input TPM type is unknown.
type ErrInvalidTPMType struct {
	Err error
}

func (err ErrInvalidTPMType) Error() string {
	return fmt.Sprintf("invalid TPM type: %v", err.Err)
}

func (err ErrInvalidTPMType) Unwrap() error {
	return err.Err
}

// ErrSameImage means the image was not saved because it is the same as
// the original imaged, and therefore to avoid double-saving the same image,
// this image was skipped.
type ErrSameImage struct{}

func (err ErrSameImage) Error() string {
	return "the image is the same as the original one, no need to save it"
}

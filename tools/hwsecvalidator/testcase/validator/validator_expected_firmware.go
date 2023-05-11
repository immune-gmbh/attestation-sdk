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
	"bytes"
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
)

// ExpectedFirmware checks if current firmware is the one we expect in this
// test case.
type ExpectedFirmware struct{}

// Validate implements Validator.
func (ExpectedFirmware) Validate(
	ctx context.Context,
	info *ValidationInfo,
) error {
	biosImg, err := biosimage.Get(info.ExpectedBootResult.CurrentState)
	if err != nil {
		return fmt.Errorf("unable to extract the BIOS image from the simulated boot process: %w", err)
	}
	measurements := info.ExpectedBootResult.CurrentState.MeasuredData.References()
	measurements.SortAndMerge()

	resolvedMeasurementsExpected := measurements.BySystemArtifact(biosImg)
	resolvedMeasurementsExpected.Resolve()

	resolvedMeasurementsCurrent := measurements.BySystemArtifact(biosImg)
	for idx := range resolvedMeasurementsCurrent {
		ref := &resolvedMeasurementsCurrent[idx]
		ref.Artifact = biosimage.NewFromParsed(info.FirmwareCurrent.UEFI)
	}
	resolvedMeasurementsCurrent.Resolve()

	if !bytes.Equal(resolvedMeasurementsCurrent.RawBytes(), resolvedMeasurementsExpected.RawBytes()) {
		return ErrExpectedFirmware{Err: fmt.Errorf("images are not equal in ranges %v", measurements)}
	}

	return nil
}

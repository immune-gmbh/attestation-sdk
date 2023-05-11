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

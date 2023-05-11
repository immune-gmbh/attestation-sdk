package validator

import (
	"bytes"
	"context"
	"fmt"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/go-tpm/tpm2"
)

// ExpectedPCR0 checks if current PCR0 value is the same as we expect for
// the current firmware image.
type ExpectedPCR0 struct{}

// Validate implements Validator.
func (ExpectedPCR0) Validate(
	ctx context.Context,
	info *ValidationInfo,
) error {
	for _, alg := range info.ExpectedTPMState.SupportedAlgos {
		logger.FromCtx(ctx).Tracef("checking the expected PCR0 for algorithm %s", alg)
		pcr0Expected, err := info.ExpectedTPMState.PCRValues.Get(0, alg)
		if err != nil {
			return ErrGetPCR0Measurements{fmt.Errorf("unable to obtain expected PCR0 value: %w", err)}
		}
		pcr0Current := info.PCR0Current[tpm2.Algorithm(alg)]

		if !bytes.Equal(pcr0Current, pcr0Expected) {
			return ErrExpectedPCR0{
				ExpectedMeasurementsLog: info.ExpectedBootResult.CurrentState.MeasuredData.String(),
				ErrPCR0Mismatch:         ErrPCR0Mismatch{Received: pcr0Current, Expected: pcr0Expected},
			}
		}
	}

	return nil
}

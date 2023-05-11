package testcase

import (
	"context"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/errors"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/validator"
)

// Positive tests the happy-path (when nothing is corrupted).
type Positive struct{}

// Setup implements TestCase.
func (Positive) Setup(ctx context.Context, image []byte) error {
	return nil
}

// Matches implements TestCase
func (Positive) Matches(fwInfo types.FirmwareInfoProvider) bool {
	return true
}

// Validate implements TestCase.
func (t Positive) Validate(ctx context.Context, origImage []byte, opts ...types.Option) error {

	info, err := validator.GetValidationInfo(ctx, t, origImage, opts)
	if err != nil {
		return errors.ErrValidationInfo{Err: err}
	}

	return validator.CommonHostBootUpExpected().Validate(ctx, info)
}

// Severity implements TestCase.
func (Positive) Severity() types.Severity {
	return types.SeverityBlocker
}

var _ types.TestCase = Positive{}

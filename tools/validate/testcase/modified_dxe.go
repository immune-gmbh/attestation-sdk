package testcase

import (
	"context"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase/errors"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase/uefiedit"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase/validator"

	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
	"github.com/klauspost/cpuid/v2"
)

// ModifiedDXE a test case where we imitate compromised DXE by introducing
// benign changes (like changing order of files and/or recompressing)
type ModifiedDXE struct{}

// Setup implements TestCase.
func (t ModifiedDXE) Setup(ctx context.Context, image []byte) error {
	err := uefiedit.InjectBenignVolumeChange(image, 0, ffsConsts.GUIDDXEContainer, ffsConsts.GUIDDXE)
	if err != nil {
		return fmt.Errorf("unable to inject a benign corruption into DXE: %w", err)
	}
	return nil
}

// Matches implements TestCase
func (ModifiedDXE) Matches(fwInfo types.FirmwareInfoProvider) bool {
	return false
	isIntel, err := types.IsArchitecture(fwInfo, cpuid.Intel)
	if err != nil {
		panic(fmt.Sprintf("cannot determine if the architecture is Intel: %v", err))
	}
	return isIntel
}

// Validate implements TestCase.
func (t ModifiedDXE) Validate(ctx context.Context, origImage []byte, opts ...types.Option) error {
	info, err := validator.GetValidationInfo(ctx, t, origImage, opts)
	if err != nil {
		return errors.ErrValidationInfo{Err: err}
	}

	return validator.CommonHostBootUpExpected().Validate(ctx, info)
}

// Severity implements TestCase.
func (ModifiedDXE) Severity() types.Severity {
	return types.SeverityBlocker
}

var _ types.TestCase = ModifiedDXE{}

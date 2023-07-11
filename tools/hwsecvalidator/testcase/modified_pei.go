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
package testcase

import (
	"context"
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/errors"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/types"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/uefiedit"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/validator"

	"github.com/linuxboot/fiano/pkg/guid"
)

// ModifiedPEITemplate is a test case template where we imitate compromised PEI by introducing
// benign changes (like changing order of files and/or recompressing)
type ModifiedPEITemplate struct {
	validators validator.Validators
}

// Setup ModifiedPEITemplate TestCase.
func (t ModifiedPEITemplate) Setup(ctx context.Context, image []byte) error {
	err := uefiedit.InjectBenignVolumeChange(image, 0, *guid.MustParse("61C0F511-A691-4F54-974F-B9A42172CE53"))
	if err != nil {
		return fmt.Errorf("unable to inject a benign corruption into PEI: %w", err)
	}
	return nil
}

// Validate implements TestCase.
func (t ModifiedPEITemplate) Validate(ctx context.Context, origImage []byte, opts ...types.Option) error {
	info, err := validator.GetValidationInfo(ctx, t, origImage, opts)
	if err != nil {
		return errors.ErrValidationInfo{Err: err}
	}

	return t.validators.Validate(ctx, info)
}

// Severity implements TestCase.
func (t ModifiedPEITemplate) Severity() types.Severity {
	return types.SeverityBlocker
}

// NewNonBootableModifiedPEI constructs TestCase when PEI modification should lead to non-bootable host
func NewNonBootableModifiedPEI(extraValidators ...validator.Validator) ModifiedPEITemplate {
	return ModifiedPEITemplate{
		validators: validator.CommonHostBootUpNotExpected(extraValidators...),
	}
}

// BootableModifiedPEI is a test case when PEI modifications are expected to lead to a bootable host
type BootableModifiedPEI struct {
	ModifiedPEITemplate
}

// Matches implements TestCase
func (tc BootableModifiedPEI) Matches(fwInfo types.FirmwareInfoProvider) bool {

	isAmdPsb, err := types.SupportsFeature(fwInfo, types.AmdPSBMilan)
	if err != nil {
		panic(fmt.Sprintf("cannot determine if the architecture supports AMD PSB: %v", err))
	}

	if isAmdPsb {
		// AMD PSB does not lead to a bootable PEI
		return false
	}

	uefiMeasurements, err := types.SupportsFeature(fwInfo, types.UEFIMeasurements)
	if err != nil {
		panic(fmt.Sprintf("cannot determine if the architecture supports UEFI measurements: %v", err))
	}
	return uefiMeasurements

}

// NewBootableModifiedPEI creates a new BootableModifiedPEI test case that will match all the provided platforms
func NewBootableModifiedPEI() BootableModifiedPEI {
	result := BootableModifiedPEI{}
	result.validators = validator.CommonHostBootUpExpected()
	return result
}

var _ types.TestCase = BootableModifiedPEI{}

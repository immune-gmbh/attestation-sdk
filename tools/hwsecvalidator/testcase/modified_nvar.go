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
	"bytes"
	"context"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/errors"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/validator"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/klauspost/cpuid/v2"
	"github.com/linuxboot/fiano/pkg/guid"
)

// ModifiedNVAR is the test case when NVAR is modified. It should not affect
// the behavior.
type ModifiedNVAR struct{}

var (
	nvarGUID = *guid.MustParse("CEF5B9A3-476D-497F-9FDC-E98143E0422C")
)

// Setup implements TestCase.
func (t ModifiedNVAR) Setup(ctx context.Context, image []byte) error {
	fw, err := uefi.ParseUEFIFirmwareBytes(image)
	if err != nil {
		return errors.ErrParseFirmware{Err: err}
	}

	nodes, err := fw.GetByGUID(nvarGUID)
	if err != nil {
		return errors.ErrLookupGUID{GUID: nvarGUID, Err: err}
	}

	if len(nodes) == 0 {
		return errors.ErrUnexpectedGUIDCount{GUID: nvarGUID, Expected: 1, Actual: len(nodes)}
	}
	nvarVolume := nodes[0]

	idx := t.findPadding(nvarVolume.Buf(), 64)
	if idx < 0 {
		return errors.ErrPaddingNotFound{}
	}

	image[nvarVolume.Offset+uint64(idx)+32] = ^image[nvarVolume.Offset+uint64(idx)+32]
	return nil
}

func (t ModifiedNVAR) findPadding(b []byte, size uint) int {
	magic := make([]byte, size)
	for idx := range magic {
		magic[idx] = 0xff
	}
	return bytes.Index(b, magic)
}

// Matches implements TestCase
func (ModifiedNVAR) Matches(fwInfo types.FirmwareInfoProvider) bool {
	isIntel, err := types.IsArchitecture(fwInfo, cpuid.Intel)
	if err != nil {
		panic(fmt.Sprintf("cannot determine if the architecture is Intel: %v", err))
	}
	return isIntel
}

// Validate implements TestCase.
func (t ModifiedNVAR) Validate(ctx context.Context, origImage []byte, opts ...types.Option) error {
	info, err := validator.GetValidationInfo(ctx, t, origImage, opts)
	if err != nil {
		return errors.ErrValidationInfo{Err: err}
	}

	return validator.CommonHostBootUpExpected().Validate(ctx, info)
}

// Severity implements TestCase.
func (ModifiedNVAR) Severity() types.Severity {
	return types.SeverityInfo
}

var _ types.TestCase = ModifiedNVAR{}

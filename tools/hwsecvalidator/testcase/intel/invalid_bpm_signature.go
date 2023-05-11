// Package intel contains specific test-cases for the Intel platform
package intel

import (
	"context"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/errors"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/validator"

	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// InvalidBPMSignature is the test case when BPM signature is incorrect.
type InvalidBPMSignature struct{}

// Setup implements TestCase.
func (InvalidBPMSignature) Setup(ctx context.Context, image []byte) error {
	headers, err := fit.GetTable(image)
	if err != nil {
		return errors.ErrOrigFirmware{Err: errors.ErrParseFirmware{Err: fmt.Errorf("FIT parsing error: %w", err)}}
	}
	var fitBPM *fit.EntryBootPolicyManifestRecord
	for _, hdr := range headers {
		if entry, ok := hdr.GetEntry(image).(*fit.EntryBootPolicyManifestRecord); ok {
			fitBPM = entry
			break
		}
	}

	if fitBPM == nil {
		return ErrNoBPM{}
	}

	_, bpm, err := fitBPM.ParseData()
	if err != nil {
		return errors.ErrOrigFirmware{Err: errors.ErrParseFirmware{Err: fmt.Errorf("BPM parsing error: %w", err)}}
	}

	bpm.PMSE.Signature.Data[0] = ^bpm.PMSE.Signature.Data[0]

	bpmOffset := fitBPM.Headers.Address.Offset(uint64(len(image)))
	offset := bpmOffset +
		bpm.PMSEOffset() +
		bpm.PMSE.KeySignatureOffset() +
		bpm.PMSE.KeySignature.SignatureOffset() +
		bpm.PMSE.KeySignature.Signature.DataOffset()
	copy(image[offset:], bpm.PMSE.Signature.Data)

	return nil
}

// Matches implements TestCase
func (InvalidBPMSignature) Matches(fwInfo types.FirmwareInfoProvider) bool {
	isCBnT, err := types.SupportsFeature(fwInfo, types.IntelCBnT)
	if err != nil {
		panic(fmt.Sprintf("cannot determine if the architecture supports Intel CBnT: %v", err))
	}
	return isCBnT
}

// Validate implements TestCase.
func (t InvalidBPMSignature) Validate(ctx context.Context, origImage []byte, opts ...types.Option) error {
	info, err := validator.GetValidationInfo(ctx, t, origImage, opts)
	if err != nil {
		return errors.ErrValidationInfo{Err: err}
	}

	return validator.CommonHostBootUpExpected().Validate(ctx, info)
}

// Severity implements TestCase.
func (InvalidBPMSignature) Severity() types.Severity {
	return types.SeverityBlocker
}

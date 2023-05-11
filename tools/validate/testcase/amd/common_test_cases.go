package amd

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase/types"
)

// PSBModifiedPEI specifies scenario when modifying PEI should lead to a non-bootable host because of PSB
type PSBModifiedPEI struct {
	testcase.ModifiedPEITemplate
}

// Matches Implements types.TestCase
func (t PSBModifiedPEI) Matches(fwInfo types.FirmwareInfoProvider) bool {
	isPsb, err := types.SupportsFeature(fwInfo, types.AmdPSBMilan)
	if err != nil {
		panic(fmt.Sprintf("cannot determine if the architecture supports AMD PSB: %v", err))
	}
	return isPsb
}

// NewPSBModifiedPEI created PSBModifiedPEI testcase for AMD Platform Secure Boot enabled
func NewPSBModifiedPEI() PSBModifiedPEI {
	modifiedPEI := testcase.NewNonBootableModifiedPEI(NewPSPSignatureVerificationFailedSELValidator())
	return PSBModifiedPEI{modifiedPEI}
}

var _ types.TestCase = NewPSBModifiedPEI()

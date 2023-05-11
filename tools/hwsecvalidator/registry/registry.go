package registry

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/amd"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/intel"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/types"
)

var all = types.TestCases{}

func init() {
	add(testcase.Positive{})
	add(testcase.ModifiedDXE{})
	add(testcase.ModifiedNVAR{})
	add(testcase.NewBootableModifiedPEI())
	add(amd.NewPSBModifiedPEI())
	add(intel.InvalidBPMSignature{})
	add(amd.NewModifiedPSPBootLoader())
	add(amd.NewModifiedABLPublicKey())
	add(amd.NewModifiedSMUOffchipFirmware())
	add(amd.NewModifiedUnlockDebugImage())
	add(amd.NewModifiedSecurityPolicyBinary())
	add(amd.NewModifiedMP5Firmware())
	add(amd.NewModifiedPSPAGESABinary0())
	add(amd.NewModifiedSEVCode())
	add(amd.NewModifiedDXIOPHYSRAMFirmware())
	add(amd.NewModifiedDRTMTA())
	add(amd.NewModifiedKeyDatabase())
	add(amd.NewModifiedPMUFirmwareInstructions())
	add(amd.NewModifiedPMUFirmwareData())
}

// Add adds input testcase to the global registry
func add(addedTestCase types.TestCase) {
	name := types.NameOf(addedTestCase)
	for _, tc := range all {
		if types.NameOf(tc) == name {
			panic(fmt.Errorf("duplicate testcase name '%s'", name))
		}
	}
	all = append(all, addedTestCase)
}

// All returns full collection of all test cases
func All() types.TestCases {
	return all.Copy()
}

// AllForFirmware returns full collection of all test cases that are suitable to run for specific firmware
func AllForFirmware(fwInfo types.FirmwareInfoProvider) types.TestCases {
	var result types.TestCases
	for _, tc := range All() {
		if tc.Matches(fwInfo) {
			result = append(result, tc)
		}
	}
	return result
}

// WithSeverity returns the collection of all test cases which has
// severity equals or higher to the selected one.
func WithSeverity(s types.Severity) types.TestCases {
	var r types.TestCases
	for _, v := range All() {
		if v.Severity() >= s {
			r = append(r, v)
		}
	}
	return r
}

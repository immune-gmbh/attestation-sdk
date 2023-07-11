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
package registry

import (
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/amd"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/intel"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/types"
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

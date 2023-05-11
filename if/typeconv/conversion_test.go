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
package typeconv

import (
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/measurements"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

func TestFlowConversion(t *testing.T) {
	for flow := measurements.Flow(0); ; flow++ {
		if _, err := measurements.FlowFromString(flow.String()); err != nil {
			// reach the end of possible Flow values
			break
		}

		fasFlow, err := FromThriftFlow(flow)
		require.NoError(t, err)

		origFlow, err := ToThriftFlow(fasFlow)
		require.NoError(t, err)

		require.Equal(t, origFlow, flow)
	}
}

func TestTPMTypeConversion(t *testing.T) {
	for _, tpmType := range []tpmdetection.Type{tpmdetection.TypeNoTPM, tpmdetection.TypeTPM12, tpmdetection.TypeTPM20} {
		fasTPMType, err := ToThriftTPMType(tpmType)
		require.NoError(t, err)

		resultTPMType, err := FromThriftTPMType(fasTPMType)
		require.NoError(t, err)

		require.Equal(t, tpmType, resultTPMType)
	}
}

func TestRegistersConversion(t *testing.T) {
	txtRegister := registers.ParseACMPolicyStatusRegister(12345)
	acmRegisters := registers.ParseBootGuardPBEC(54321)

	initialRegisters := registers.Registers{txtRegister, acmRegisters}

	fasRegisters, err := ToThriftRegisters(initialRegisters)
	require.NoError(t, err)

	resultRegisters, err := FromThriftRegisters(fasRegisters)
	require.NoError(t, err)

	require.Equal(t, initialRegisters, resultRegisters)
}

func TestConvertToAFASTPMEventLog(t *testing.T) {
	initial := &tpmeventlog.TPMEventLog{
		Events: []*tpmeventlog.Event{
			{
				PCRIndex: 0,
				Type:     tpmeventlog.EV_NO_ACTION,
				Data:     []byte{0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x4C, 0x6F, 0x63, 0x61, 0x6C, 0x69, 0x74, 0x79, 0x00, 0x03, 0x00},
				Digest: &tpmeventlog.Digest{
					HashAlgo: tpm2.AlgSHA1,
					Digest:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				},
			},
		},
	}

	fasEventLog := ToThriftTPMEventLog(initial)
	require.NotNil(t, fasEventLog)

	resultEventLog := FromThriftTPMEventLog(fasEventLog)
	require.Equal(t, initial, resultEventLog)
}

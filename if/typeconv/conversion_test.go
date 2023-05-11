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
	for _, flow := range measurements.FlowValues {
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

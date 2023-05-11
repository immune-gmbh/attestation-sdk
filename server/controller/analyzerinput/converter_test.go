package analyzerinput

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"

	"privatecore/firmware/samples"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/pspsignature"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/reproducepcr"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/stretchr/testify/require"
)

func TestNewDiffMeasuredBootInput(t *testing.T) {
	input := afas.DiffMeasuredBootInput{
		OriginalFirmwareImage: &[]int32{0}[0],
		ActualFirmwareImage:   1,
		StatusRegisters:       &[]int32{2}[0],
		TPMDevice:             &[]int32{3}[0],
		TPMEventLog:           &[]int32{4}[0],
		ActualPCR0:            &[]int32{5}[0],
	}

	dummyOrigImage := []byte{0x1, 0x2, 0x3, 0x4}
	dummyActualImage := []byte{0x4, 0x3, 0x2, 0x1}
	dummyRegisters := registers.Registers{
		registers.ParseACMPolicyStatusRegister(12345),
	}
	dummyTPMDevice := tpmdetection.TypeTPM20
	dummyActualPCR0 := []byte{0x11, 0x12, 0x13, 0x14}

	tpmEventLogRaw, err := samples.GetFile("tpmeventlog", "F0E_3A10_binary_bios_measurements.xz")
	require.NoError(t, err)
	dummyEventLog, err := tpmeventlog.Parse(bytes.NewReader(tpmEventLogRaw))
	require.NoError(t, err)

	expectedInput, err := diffmeasuredboot.NewExectorInput(
		analysis.BytesBlob(dummyOrigImage),
		analysis.BytesBlob(dummyActualImage),
		dummyRegisters,
		dummyTPMDevice,
		dummyEventLog,
		dummyActualPCR0,
		nil,
	)
	require.NoError(t, err)

	artifactsAccessor := &artifactsAccessorMock{
		getFirmware: func(ctx context.Context, artIdx int) (analysis.Blob, error) {
			if artIdx == int(*input.OriginalFirmwareImage) {
				return analysis.BytesBlob(dummyOrigImage), nil
			}
			if artIdx == int(input.ActualFirmwareImage) {
				return analysis.BytesBlob(dummyActualImage), nil
			}
			require.Fail(t, "unexpected artifact idx %d", artIdx)
			return nil, fmt.Errorf("unexpected artifact idx %d", artIdx)
		},
		getRegisters: func(ctx context.Context, artIdx int) (registers.Registers, error) {
			require.Equal(t, int(*input.StatusRegisters), artIdx)
			return dummyRegisters, nil
		},
		getTPMDevice: func(ctx context.Context, artIdx int) (tpmdetection.Type, error) {
			require.Equal(t, int(*input.TPMDevice), artIdx)
			return dummyTPMDevice, nil
		},
		getTPMEventLog: func(ctx context.Context, artIdx int) (*tpmeventlog.TPMEventLog, error) {
			require.Equal(t, int(*input.TPMEventLog), artIdx)
			return dummyEventLog, nil
		},
		getPCR: func(ctx context.Context, artIdx int) ([]byte, uint32, error) {
			require.Equal(t, int(*input.ActualPCR0), artIdx)
			return dummyActualPCR0, 0, nil
		},
	}

	result, err := NewDiffMeasuredBootInput(context.Background(), artifactsAccessor, input)
	require.NoError(t, err)
	require.Equal(t, expectedInput, result)
}

func TestNewReproducePCRInput(t *testing.T) {
	input := afas.ReproducePCRInput{
		OriginalFirmwareImage: &[]int32{0}[0],
		ActualFirmwareImage:   1,
		StatusRegisters:       &[]int32{2}[0],
		TPMDevice:             &[]int32{3}[0],
		TPMEventLog:           &[]int32{4}[0],
		ExpectedPCR:           5,
		MeasurementsFlow:      &[]int32{6}[0],
	}

	dummyOrigImage := []byte{0x1, 0x2, 0x3, 0x4}
	dummyActualImage := []byte{0x4, 0x3, 0x2, 0x1}
	dummyRegisters := registers.Registers{
		registers.ParseACMPolicyStatusRegister(12345),
	}
	dummyTPMDevice := tpmdetection.TypeTPM20
	dummyExpectedPCR0 := []byte{0x11, 0x12, 0x13, 0x14}

	tpmEventLogRaw, err := samples.GetFile("tpmeventlog", "F0E_3A10_binary_bios_measurements.xz")
	require.NoError(t, err)
	dummyEventLog, err := tpmeventlog.Parse(bytes.NewReader(tpmEventLogRaw))
	require.NoError(t, err)

	dummyMeasurementsFlow := pcr.FlowIntelLegacyTXTEnabled

	expectedInput, err := reproducepcr.NewExectorInput(
		analysis.BytesBlob(dummyOrigImage),
		analysis.BytesBlob(dummyActualImage),
		dummyRegisters,
		dummyTPMDevice,
		dummyEventLog,
		dummyMeasurementsFlow,
		dummyExpectedPCR0,
	)
	require.NoError(t, err)

	artifactsAccessor := &artifactsAccessorMock{
		getFirmware: func(ctx context.Context, artIdx int) (analysis.Blob, error) {
			if artIdx == int(*input.OriginalFirmwareImage) {
				return analysis.BytesBlob(dummyOrigImage), nil
			}
			if artIdx == int(input.ActualFirmwareImage) {
				return analysis.BytesBlob(dummyActualImage), nil
			}
			require.Fail(t, "unexpected artifact idx %d", artIdx)
			return nil, fmt.Errorf("unexpected artifact idx %d", artIdx)
		},
		getRegisters: func(ctx context.Context, artIdx int) (registers.Registers, error) {
			require.Equal(t, int(*input.StatusRegisters), artIdx)
			return dummyRegisters, nil
		},
		getTPMDevice: func(ctx context.Context, artIdx int) (tpmdetection.Type, error) {
			require.Equal(t, int(*input.TPMDevice), artIdx)
			return dummyTPMDevice, nil
		},
		getTPMEventLog: func(ctx context.Context, artIdx int) (*tpmeventlog.TPMEventLog, error) {
			require.Equal(t, int(*input.TPMEventLog), artIdx)
			return dummyEventLog, nil
		},
		getPCR: func(ctx context.Context, artIdx int) ([]byte, uint32, error) {
			require.Equal(t, int(input.ExpectedPCR), artIdx)
			return dummyExpectedPCR0, 0, nil
		},
		getMeasurementsFlow: func(ctx context.Context, inputIdx int) (types.BootFlow, error) {
			require.Equal(t, int(*input.MeasurementsFlow), inputIdx)
			return types.BootFlow(flows.FromOld(dummyMeasurementsFlow)), nil
		},
	}

	result, err := NewReproducePCRInput(context.Background(), artifactsAccessor, input)
	require.NoError(t, err)
	require.Equal(t, expectedInput, result)
}

func TestNewIntelACMInput(t *testing.T) {
	input := afas.IntelACMInput{
		OriginalFirmwareImage: &[]int32{0}[0],
		ActualFirmwareImage:   1,
	}

	dummyOrigImage := []byte{0x1, 0x2, 0x3, 0x4}
	dummyActualImage := []byte{0x4, 0x3, 0x2, 0x1}

	expectedInput, err := intelacm.NewExectorInput(
		analysis.BytesBlob(dummyOrigImage),
		analysis.BytesBlob(dummyActualImage),
	)
	require.NoError(t, err)

	artifactsAccessor := &artifactsAccessorMock{
		getFirmware: func(ctx context.Context, artIdx int) (analysis.Blob, error) {
			if artIdx == int(*input.OriginalFirmwareImage) {
				return analysis.BytesBlob(dummyOrigImage), nil
			}
			if artIdx == int(input.ActualFirmwareImage) {
				return analysis.BytesBlob(dummyActualImage), nil
			}
			require.Fail(t, "unexpected artifact idx %d", artIdx)
			return nil, fmt.Errorf("unexpected artifact idx %d", artIdx)
		},
	}

	result, err := NewIntelACMInput(context.Background(), artifactsAccessor, input)
	require.NoError(t, err)
	require.Equal(t, expectedInput, result)
}

func TestNewPSPSignatureInput(t *testing.T) {
	input := afas.PSPSignatureInput{
		ActualFirmwareImage: 0,
	}
	dummyOrigImage := []byte{0x1, 0x2, 0x3, 0x4}

	expectedInput, err := pspsignature.NewExecutorInput(analysis.BytesBlob(dummyOrigImage))
	require.NoError(t, err)

	artifactsAccessor := &artifactsAccessorMock{
		getFirmware: func(ctx context.Context, artIdx int) (analysis.Blob, error) {
			require.Equal(t, int(input.ActualFirmwareImage), artIdx)
			return analysis.BytesBlob(dummyOrigImage), nil
		},
	}
	result, err := NewPSPSignatureInput(context.Background(), artifactsAccessor, input)
	require.NoError(t, err)
	require.Equal(t, expectedInput, result)
}

func TestNewBIOSRTMVolumeInput(t *testing.T) {
	input := afas.BIOSRTMVolumeInput{
		ActualFirmwareImage: 0,
	}
	dummyOrigImage := []byte{0x1, 0x2, 0x3, 0x4}

	expectedInput, err := pspsignature.NewExecutorInput(analysis.BytesBlob(dummyOrigImage))
	require.NoError(t, err)

	artifactsAccessor := &artifactsAccessorMock{
		getFirmware: func(ctx context.Context, artIdx int) (analysis.Blob, error) {
			require.Zero(t, artIdx)
			return analysis.BytesBlob(dummyOrigImage), nil
		},
	}
	result, err := NewBIOSRTMVolumeInput(context.Background(), artifactsAccessor, input)
	require.NoError(t, err)
	require.Equal(t, expectedInput, result)
}

func TestNewAPCBSecurityTokensInput(t *testing.T) {
	input := afas.APCBSecurityTokensInput{
		ActualFirmwareImage: 0,
	}
	dummyOrigImage := []byte{0x1, 0x2, 0x3, 0x4}

	expectedInput, err := pspsignature.NewExecutorInput(analysis.BytesBlob(dummyOrigImage))
	require.NoError(t, err)

	artifactsAccessor := &artifactsAccessorMock{
		getFirmware: func(ctx context.Context, artIdx int) (analysis.Blob, error) {
			require.Zero(t, artIdx)
			return analysis.BytesBlob(dummyOrigImage), nil
		},
	}
	result, err := NewAPCBSecurityTokensInput(context.Background(), artifactsAccessor, input)
	require.NoError(t, err)
	require.Equal(t, expectedInput, result)
}

type artifactsAccessorMock struct {
	getFirmware         func(ctx context.Context, artIdx int) (analysis.Blob, error)
	getRegisters        func(ctx context.Context, artIdx int) (registers.Registers, error)
	getTPMDevice        func(ctx context.Context, artIdx int) (tpmdetection.Type, error)
	getTPMEventLog      func(ctx context.Context, artIdx int) (*tpmeventlog.TPMEventLog, error)
	getPCR              func(ctx context.Context, artIdx int) ([]byte, uint32, error)
	getMeasurementsFlow func(ctx context.Context, inputIdx int) (types.BootFlow, error)
}

func (m artifactsAccessorMock) GetFirmware(ctx context.Context, artIdx int) (analysis.Blob, error) {
	return m.getFirmware(ctx, artIdx)
}

func (m artifactsAccessorMock) GetRegisters(ctx context.Context, artIdx int) (registers.Registers, error) {
	return m.getRegisters(ctx, artIdx)
}

func (m artifactsAccessorMock) GetTPMDevice(ctx context.Context, artIdx int) (tpmdetection.Type, error) {
	return m.getTPMDevice(ctx, artIdx)
}

func (m artifactsAccessorMock) GetTPMEventLog(ctx context.Context, artIdx int) (*tpmeventlog.TPMEventLog, error) {
	return m.getTPMEventLog(ctx, artIdx)
}

func (m artifactsAccessorMock) GetPCR(ctx context.Context, artIdx int) ([]byte, uint32, error) {
	return m.getPCR(ctx, artIdx)
}

func (m artifactsAccessorMock) GetMeasurementsFlow(ctx context.Context, inputIdx int) (types.BootFlow, error) {
	return m.getMeasurementsFlow(ctx, inputIdx)
}

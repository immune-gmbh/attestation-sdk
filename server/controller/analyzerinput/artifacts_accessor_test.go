package analyzerinput

import (
	"bytes"
	"context"
	"fmt"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/measurements"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/typeconv"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"privatecore/firmware/samples"

	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/stretchr/testify/require"
)

func TestArtifactsAccessorCreation(t *testing.T) {
	t.Run("no_artifacts", func(t *testing.T) {
		mock := &firmwaresAccessorMock{}
		accessor, err := NewArtifactsAccessor(nil, mock)
		require.NoError(t, err)
		require.NotNil(t, accessor)
	})

	t.Run("no_firmware_image_accessor", func(t *testing.T) {
		accessor, err := NewArtifactsAccessor(nil, nil)
		require.Error(t, err)
		require.Nil(t, accessor)
	})
}

func TestArtifactsAccessorOutOfRangeIndex(t *testing.T) {
	tpmDevice := afas.TPMType_TPM20
	artifacts := []afas.Artifact{
		{
			TPMDevice: &tpmDevice,
		},
	}

	mock := &firmwaresAccessorMock{}
	accessor, err := NewArtifactsAccessor(artifacts, mock)
	require.NoError(t, err)
	require.NotNil(t, accessor)

	_, err = accessor.GetTPMDevice(context.Background(), 1)
	require.Error(t, err)
}

type firmware struct {
	Meta    models.ImageMetadata
	Content []byte
}

func TestArtifactsAccessorGetFirmwareImage(t *testing.T) {
	t.Run("version_plus_date", func(t *testing.T) {
		dummyImage := []byte{0x1, 0x2, 0x3, 0x4}
		dummyVersion := "version"
		dummyDate := "date"
		mock := &firmwaresAccessorMock{
			getByVersionAndDate: func(ctx context.Context, firmwareVersion, firmwareDateString string) (analysis.Blob, error) {
				require.Equal(t, dummyVersion, firmwareVersion)
				require.Equal(t, dummyDate, firmwareDateString)
				return analysis.BytesBlob(dummyImage), nil
			},
		}

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					FwVersion: &afas.FirmwareVersion{
						Version: dummyVersion,
						Date:    dummyDate,
					},
				},
			},
		}
		accessor, err := NewArtifactsAccessor(artifacts, mock)
		require.NoError(t, err)
		require.NotNil(t, accessor)

		firmware, err := accessor.GetFirmware(context.Background(), 0)
		require.NoError(t, err)
		firmwareBytes := firmware.Bytes()
		require.Equal(t, dummyImage, firmwareBytes)
	})

	t.Run("compressed_blob", func(t *testing.T) {
		dummyImage := []byte{0x1, 0x2, 0x3, 0x4}
		mock := &firmwaresAccessorMock{
			getByBlob: func(ctx context.Context, image []byte) (analysis.Blob, error) {
				require.Equal(t, dummyImage, image)
				return analysis.BytesBlob(image), nil
			},
		}

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        dummyImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
		}
		accessor, err := NewArtifactsAccessor(artifacts, mock)
		require.NoError(t, err)
		require.NotNil(t, accessor)

		firmware, err := accessor.GetFirmware(context.Background(), 0)
		require.NoError(t, err)
		firmwareBytes := firmware.Bytes()
		require.Equal(t, dummyImage, firmwareBytes)
	})

	t.Run("filename", func(t *testing.T) {
		dummyImage := []byte{0x1, 0x2, 0x3, 0x4}
		dummyFilename := "dummy_archive.gz"
		mock := &firmwaresAccessorMock{
			getByFilename: func(ctx context.Context, filename string) (analysis.Blob, error) {
				require.Equal(t, dummyFilename, filename)
				return analysis.BytesBlob(dummyImage), nil
			},
		}

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Filename: &dummyFilename,
				},
			},
		}
		accessor, err := NewArtifactsAccessor(artifacts, mock)
		require.NoError(t, err)
		require.NotNil(t, accessor)

		firmware, err := accessor.GetFirmware(context.Background(), 0)
		require.NoError(t, err)
		firmwareBytes := firmware.Bytes()
		require.Equal(t, dummyImage, firmwareBytes)
	})

	t.Run("manifold", func(t *testing.T) {
		dummyImage := []byte{0x1, 0x2, 0x3, 0x4}
		dummyManifoldID := types.NewImageIDFromImage(dummyImage)
		knownFirmwares := map[types.ImageID]firmware{}
		mock := &firmwaresAccessorMock{
			getByID: func(ctx context.Context, imageID types.ImageID) (analysis.Blob, error) {
				require.Equal(t, dummyManifoldID, imageID)
				return analysis.BytesBlob(dummyImage), nil
			},
		}

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					ManifoldID: dummyManifoldID[:],
				},
			},
		}
		accessor, err := NewArtifactsAccessor(artifacts, mock)
		require.NoError(t, err)
		require.NotNil(t, accessor)

		firmware, err := accessor.GetFirmware(context.Background(), 0)
		require.NoError(t, err, fmt.Sprintf("knownFirmwares:%#+v", knownFirmwares))
		firmwareBytes := firmware.Bytes()
		require.Equal(t, dummyImage, firmwareBytes)
	})

	t.Run("everstore", func(t *testing.T) {
		dummyImage := []byte{0x1, 0x2, 0x3, 0x4}
		dummyEverstoreHandle := "DUMMY_HANDLE"
		mock := &firmwaresAccessorMock{
			getByEverstoreHandle: func(ctx context.Context, handle string) (analysis.Blob, error) {
				return analysis.BytesBlob(dummyImage), nil
			},
		}

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					EverstoreHandle: &dummyEverstoreHandle,
				},
			},
		}

		accessor, err := NewArtifactsAccessor(artifacts, mock)
		require.NoError(t, err)
		require.NotNil(t, accessor)

		firmware, err := accessor.GetFirmware(context.Background(), 0)
		require.NoError(t, err)
		firmwareBytes := firmware.Bytes()
		require.Equal(t, dummyImage, firmwareBytes)
	})
}

func TestArtifactsAccessorGetRegisters(t *testing.T) {
	mock := &firmwaresAccessorMock{}

	dummyRegister := registers.ParseACMPolicyStatusRegister(12345)
	regValue, err := registers.ValueBytes(dummyRegister)
	require.NoError(t, err)

	artifacts := []afas.Artifact{
		{
			StatusRegisters: []*afas.StatusRegister{
				{
					Id:    string(registers.AcmPolicyStatusRegisterID),
					Value: regValue,
				},
			},
		},
	}
	accessor, err := NewArtifactsAccessor(artifacts, mock)
	require.NoError(t, err)
	require.NotNil(t, accessor)

	regs, err := accessor.GetRegisters(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, registers.Registers{
		dummyRegister,
	}, regs)
}

func TestArtifactsAccessorGetTPMDevice(t *testing.T) {
	tpmDevice := afas.TPMType_TPM20
	artifacts := []afas.Artifact{
		{
			TPMDevice: &tpmDevice,
		},
	}

	mock := &firmwaresAccessorMock{}
	accessor, err := NewArtifactsAccessor(artifacts, mock)
	require.NoError(t, err)
	require.NotNil(t, accessor)

	resultDevice, err := accessor.GetTPMDevice(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, tpmdetection.TypeTPM20, resultDevice)
}

func TestArtifactsAccessorGetTPMEventLog(t *testing.T) {
	tpmEventLogRaw, err := samples.GetFile("tpmeventlog", "F0E_3A10_binary_bios_measurements.xz")
	require.NoError(t, err)

	eventLog, err := tpmeventlog.Parse(bytes.NewReader(tpmEventLogRaw))
	require.NoError(t, err)

	artifacts := []afas.Artifact{
		{
			TPMEventLog: typeconv.ToThriftTPMEventLog(eventLog),
		},
	}

	mock := &firmwaresAccessorMock{}
	accessor, err := NewArtifactsAccessor(artifacts, mock)
	require.NoError(t, err)
	require.NotNil(t, accessor)

	resultEventlog, err := accessor.GetTPMEventLog(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, eventLog, resultEventlog)
}

func TestArtifactsAccessorGetMeasurementsFlow(t *testing.T) {
	artifacts := []afas.Artifact{
		{
			MeasurementsFlow: &[]measurements.Flow{measurements.Flow_INTEL_CBNT0T}[0],
		},
	}

	mock := &firmwaresAccessorMock{}
	accessor, err := NewArtifactsAccessor(artifacts, mock)
	require.NoError(t, err)
	require.NotNil(t, accessor)

	resultFlow, err := accessor.GetMeasurementsFlow(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, flows.IntelCBnT, bootflowtypes.Flow(resultFlow))
}

type firmwaresAccessorMock struct {
	getByBlob            func(ctx context.Context, content []byte) (analysis.Blob, error)
	getByID              func(ctx context.Context, manifoldID types.ImageID) (analysis.Blob, error)
	getByVersionAndDate  func(ctx context.Context, firmwareVersion, firmwareDateString string) (analysis.Blob, error)
	getByFilename        func(ctx context.Context, filename string) (analysis.Blob, error)
	getByEverstoreHandle func(ctx context.Context, handle string) (analysis.Blob, error)
}

func (m firmwaresAccessorMock) GetByBlob(ctx context.Context, image []byte) (analysis.Blob, error) {
	return m.getByBlob(ctx, image)
}

func (m firmwaresAccessorMock) GetByID(ctx context.Context, imageID types.ImageID) (analysis.Blob, error) {
	return m.getByID(ctx, imageID)
}

func (m firmwaresAccessorMock) GetByVersionAndDate(ctx context.Context, firmwareVersion, firmwareDateString string) (analysis.Blob, error) {
	return m.getByVersionAndDate(ctx, firmwareVersion, firmwareDateString)
}

func (m firmwaresAccessorMock) GetByFilename(ctx context.Context, filename string) (analysis.Blob, error) {
	return m.getByFilename(ctx, filename)
}

func (m firmwaresAccessorMock) GetByEverstoreHandle(ctx context.Context, handle string) (analysis.Blob, error) {
	return m.getByEverstoreHandle(ctx, handle)
}

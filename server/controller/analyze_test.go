package controller

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/measurements"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/diffanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm/report/intelacmanalysis"
	gatingMocks "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/gating/mocks"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"privatecore/firmware/samples"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAnalyze(t *testing.T) {
	storage := &storageMock{}
	serf := &serfMock{}
	firmwareFetcher := &firmwareStorageMock{}

	rfe := &rfeMock{}
	_rtpfw := newRTPFWMock()

	diffScubaReporter := &scubaMock{}
	hostConfigScubaReporter := &scubaMock{}

	datacalculator, err := analysis.NewDataCalculator(10)
	require.NoError(t, err)

	// gating setup
	gate := "ramdisk_attestation_report_config"
	fakeGateChecker := gatingMocks.NewFakeGateChecker()
	fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

	controller, err := newInternal(
		context.Background(),
		0,
		storage,
		serf,
		firmwareFetcher,
		rfe,
		_rtpfw,
		&dummyRTPDB{},
		datacalculator,
		fakeGateChecker,
		diffScubaReporter,
		"dummy_scuba1",
		hostConfigScubaReporter,
		time.Hour,
		time.Hour,
		10,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, controller)
	defer func() {
		assert.NoError(t, controller.Close())
	}()

	firmwareImage, err := samples.GetFile("firmwares", "F20_3A15.bin.xz")
	require.NoError(t, err)

	t.Run("measured_boot", func(t *testing.T) {
		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        firmwareImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
			{
				TPMDevice: &[]afas.TPMType{afas.TPMType_TPM20}[0],
			},
		}
		analyzers := []afas.AnalyzerInput{
			{
				DiffMeasuredBoot: &afas.DiffMeasuredBootInput{
					OriginalFirmwareImage: &[]int32{0}[0],
					ActualFirmwareImage:   0,
					StatusRegisters:       nil,
					TPMDevice:             &[]int32{1}[0],
					TPMEventLog:           nil,
				},
			},
		}

		report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
		require.NoError(t, err)
		require.NotNil(t, report)

		require.NotEmpty(t, report.JobID)
		require.Len(t, report.Results, 1)

		analyzerResult := report.Results[0]
		require.False(t, analyzerResult.GetAnalyzerOutcome().IsSetErr(), analyzerResult.GetAnalyzerOutcome().GetErr())
		require.True(t, analyzerResult.GetAnalyzerOutcome().IsSetReport())

		customReport := analyzerResult.GetAnalyzerOutcome().Report.Custom
		require.Equal(t, 1, customReport.CountSetFieldsReportInfo())
		require.True(t, customReport.IsSetDiffMeasuredBoot())

		require.Equal(t, diffanalysis.DiffDiagnosis_Match, customReport.DiffMeasuredBoot.Diagnosis)
		require.Empty(t, customReport.DiffMeasuredBoot.DiffEntries)
	})

	t.Run("reproduce_pcr", func(t *testing.T) {
		txtEnabledPCR, err := hex.DecodeString("3254E2292F39292550249CECC9FE94ABA735893C")
		require.NoError(t, err)

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        firmwareImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
			{
				TPMDevice: &[]afas.TPMType{afas.TPMType_TPM20}[0],
			},
			{
				Pcr: &[]afas.PCR{
					{
						Value: txtEnabledPCR,
					},
				}[0],
			},
		}

		analyzers := []afas.AnalyzerInput{
			{
				ReproducePCR: &afas.ReproducePCRInput{
					OriginalFirmwareImage: &[]int32{0}[0],
					ActualFirmwareImage:   0,
					StatusRegisters:       nil,
					TPMDevice:             &[]int32{1}[0],
					TPMEventLog:           nil,
					ExpectedPCR:           2,
				},
			},
		}

		report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
		require.NoError(t, err)
		require.NotNil(t, report)

		require.NotEmpty(t, report.JobID)
		require.Len(t, report.Results, 1)

		analyzerResult := report.Results[0]
		require.False(t, analyzerResult.GetAnalyzerOutcome().IsSetErr())
		require.True(t, analyzerResult.GetAnalyzerOutcome().IsSetReport())

		customReport := analyzerResult.GetAnalyzerOutcome().Report.Custom
		require.Equal(t, 1, customReport.CountSetFieldsReportInfo())
		require.True(t, customReport.IsSetReproducePCR())

		require.Equal(t, measurements.Flow_INTEL_LEGACY_TXT_ENABLED, customReport.ReproducePCR.ExpectedFlow)
		require.Equal(t, int8(3), customReport.ReproducePCR.ExpectedLocality)
	})

	t.Run("intel_acm", func(t *testing.T) {
		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        firmwareImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
		}

		analyzers := []afas.AnalyzerInput{
			{
				IntelACM: &afas.IntelACMInput{
					OriginalFirmwareImage: &[]int32{0}[0],
					ActualFirmwareImage:   0,
				},
			},
		}

		report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
		require.NoError(t, err)
		require.NotNil(t, report)

		require.NotEmpty(t, report.JobID)
		require.Len(t, report.Results, 1)

		analyzerResult := report.Results[0]
		require.False(t, analyzerResult.GetAnalyzerOutcome().IsSetErr())
		require.True(t, analyzerResult.GetAnalyzerOutcome().IsSetReport())

		customReport := analyzerResult.GetAnalyzerOutcome().Report.Custom
		require.Equal(t, 1, customReport.CountSetFieldsReportInfo())
		require.True(t, customReport.IsSetIntelACM())

		expectedIntelACM := &intelacmanalysis.ACMInfo{Date: 538314776, SESVN: 0, TXTSVN: 0}
		require.Equal(t, expectedIntelACM, customReport.IntelACM.Original)
		require.Equal(t, expectedIntelACM, customReport.IntelACM.Received)
	})

	t.Run("psp_signature", func(t *testing.T) {
		amdFirmwareImage, err := samples.GetFile("firmwares", "F09C_3B08.bin.xz")
		require.NoError(t, err)

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        amdFirmwareImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
		}

		analyzers := []afas.AnalyzerInput{
			{
				PSPSignature: &afas.PSPSignatureInput{
					ActualFirmwareImage: 0,
				},
			},
		}

		report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
		require.NoError(t, err)
		require.NotNil(t, report)

		require.NotEmpty(t, report.JobID)
		require.Len(t, report.Results, 1)

		analyzerResult := report.Results[0]
		require.False(t, analyzerResult.GetAnalyzerOutcome().IsSetErr())
		require.True(t, analyzerResult.GetAnalyzerOutcome().IsSetReport())

		customReport := analyzerResult.GetAnalyzerOutcome().Report.Custom
		require.Equal(t, 1, customReport.CountSetFieldsReportInfo())
		require.True(t, customReport.IsSetPSPSignature())
	})

	t.Run("bios_rtm_volume", func(t *testing.T) {
		amdFirmwareImage, err := samples.GetFile("firmwares", "F09C_3B08.bin.xz")
		require.NoError(t, err)

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        amdFirmwareImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
		}

		analyzers := []afas.AnalyzerInput{
			{
				BIOSRTMVolume: &afas.BIOSRTMVolumeInput{
					ActualFirmwareImage: 0,
				},
			},
		}

		report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
		require.NoError(t, err)
		require.NotNil(t, report)

		require.NotEmpty(t, report.JobID)
		require.Len(t, report.Results, 1)

		analyzerResult := report.Results[0]
		require.False(t, analyzerResult.GetAnalyzerOutcome().IsSetErr(), analyzerResult.GetAnalyzerOutcome().GetErr())
		require.True(t, analyzerResult.GetAnalyzerOutcome().IsSetReport())

		customReport := analyzerResult.GetAnalyzerOutcome().Report.Custom
		require.Equal(t, 1, customReport.CountSetFieldsReportInfo())
		require.True(t, customReport.IsSetBIOSRTMVolume())
	})

	t.Run("apsb_security_tokens", func(t *testing.T) {
		amdFirmwareImage, err := samples.GetFile("firmwares", "F09C_3B08.bin.xz")
		require.NoError(t, err)

		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        amdFirmwareImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
		}

		analyzers := []afas.AnalyzerInput{
			{
				APCBSecurityTokens: &afas.APCBSecurityTokensInput{
					ActualFirmwareImage: 0,
				},
			},
		}

		report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
		require.NoError(t, err)
		require.NotNil(t, report)

		require.NotEmpty(t, report.JobID)
		require.Len(t, report.Results, 1)

		analyzerResult := report.Results[0]
		require.False(t, analyzerResult.GetAnalyzerOutcome().IsSetErr())
		require.True(t, analyzerResult.GetAnalyzerOutcome().IsSetReport())

		customReport := analyzerResult.GetAnalyzerOutcome().Report.Custom
		require.Equal(t, 1, customReport.CountSetFieldsReportInfo())
		require.True(t, customReport.IsSetAPCBSecurityTokens())
	})

	t.Run("psp_analyzers_for_intel_firmware", func(t *testing.T) {
		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        firmwareImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
		}

		analyzers := []afas.AnalyzerInput{
			{
				PSPSignature: &afas.PSPSignatureInput{
					ActualFirmwareImage: 0,
				},
			},
			{
				BIOSRTMVolume: &afas.BIOSRTMVolumeInput{
					ActualFirmwareImage: 0,
				},
			},
			{
				APCBSecurityTokens: &afas.APCBSecurityTokensInput{
					ActualFirmwareImage: 0,
				},
			},
		}

		report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
		require.NoError(t, err)
		require.NotNil(t, report)

		require.NotEmpty(t, report.JobID)
		require.Len(t, report.Results, len(analyzers))

		for _, analyzerResult := range report.Results {
			require.False(t, analyzerResult.GetAnalyzerOutcome().IsSetReport(), fmt.Sprintf("%#+v", analyzerResult.GetAnalyzerOutcome().Report))
			require.True(t, analyzerResult.GetAnalyzerOutcome().IsSetErr())
			require.Equal(t, afas.ErrorClass_NotSupported, analyzerResult.GetAnalyzerOutcome().Err.ErrorClass)
		}
	})

	t.Run("incorrect_input", func(t *testing.T) {
		artifacts := []afas.Artifact{
			{
				FwImage: &afas.FirmwareImage{
					Blob: &afas.CompressedBlob{
						Blob:        firmwareImage,
						Compression: afas.CompressionType_None,
					},
				},
			},
			{
				TPMDevice: &[]afas.TPMType{afas.TPMType_TPM20}[0],
			},
		}
		analyzers := []afas.AnalyzerInput{
			{
				DiffMeasuredBoot: &afas.DiffMeasuredBootInput{
					OriginalFirmwareImage: &[]int32{1}[0], // index 1 points to TPM device which could not be converted to firmware image
					ActualFirmwareImage:   0,
					StatusRegisters:       nil,
					TPMDevice:             &[]int32{1}[0],
					TPMEventLog:           nil,
				},
			},
		}

		report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
		require.NoError(t, err)
		require.NotNil(t, report)

		require.NotEmpty(t, report.JobID)
		require.Len(t, report.Results, 1)

		analyzerResult := report.Results[0]
		require.False(t, analyzerResult.GetAnalyzerOutcome().IsSetReport())
		require.True(t, analyzerResult.GetAnalyzerOutcome().IsSetErr())

		require.Equal(t, afas.ErrorClass_InvalidInput, analyzerResult.GetAnalyzerOutcome().Err.ErrorClass)
	})
}

func TestAnalyzeSaveImage(t *testing.T) {
	serf := &serfMock{}
	firmwareFetcher := &firmwareStorageMock{}

	rfe := &rfeMock{}
	_rtpfw := newRTPFWMock()

	diffScubaReporter := &scubaMock{}
	hostConfigScubaReporter := &scubaMock{}

	datacalculator, err := analysis.NewDataCalculator(10)
	require.NoError(t, err)

	// gating setup
	gate := "ramdisk_attestation_report_config"
	fakeGateChecker := gatingMocks.NewFakeGateChecker()
	fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

	firmwareImage, err := samples.GetFile("firmwares", "F20_3A15.bin.xz")
	require.NoError(t, err)

	hashStable, err := types.NewImageStableHashFromImage(firmwareImage)
	require.NoError(t, err)

	var insertInvokedCnt int32
	storage := &storageMock{
		insert: func(ctx context.Context, imageMeta models.ImageMetadata, imageData []byte) error {
			atomic.AddInt32(&insertInvokedCnt, 1)
			require.Equal(t, types.NewImageIDFromImage(firmwareImage), imageMeta.ImageID)
			require.Equal(t, hashStable, imageMeta.HashStable)
			require.True(t, bytes.Equal(firmwareImage, imageData))
			return nil
		},
	}

	controller, err := newInternal(
		context.Background(),
		0,
		storage,
		serf,
		firmwareFetcher,
		rfe,
		_rtpfw,
		&dummyRTPDB{},
		datacalculator,
		fakeGateChecker,
		diffScubaReporter,
		"dummy_scuba1",
		hostConfigScubaReporter,
		time.Hour,
		time.Hour,
		10,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, controller)

	defer func() {
		assert.NoError(t, controller.Close())
	}()

	artifacts := []afas.Artifact{
		{
			FwImage: &afas.FirmwareImage{
				Blob: &afas.CompressedBlob{
					Blob:        firmwareImage,
					Compression: afas.CompressionType_None,
				},
			},
		},
		{
			TPMDevice: &[]afas.TPMType{afas.TPMType_TPM20}[0],
		},
	}
	analyzers := []afas.AnalyzerInput{
		{
			DiffMeasuredBoot: &afas.DiffMeasuredBootInput{
				OriginalFirmwareImage: &[]int32{0}[0],
				ActualFirmwareImage:   0,
				StatusRegisters:       nil,
				TPMDevice:             &[]int32{1}[0],
				TPMEventLog:           nil,
			},
		},
	}

	report, err := controller.Analyze(context.Background(), nil, artifacts, analyzers)
	require.NoError(t, err)
	require.NotNil(t, report)

	require.NoError(t, controller.Close())
	require.Equal(t, int32(1), insertInvokedCnt)
}

func TestInvalidInput(t *testing.T) {
	datacalculator, err := analysis.NewDataCalculator(10)
	require.NoError(t, err)

	// gating setup
	gate := "ramdisk_attestation_report_config"
	fakeGateChecker := gatingMocks.NewFakeGateChecker()
	fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

	controller, err := newInternal(
		context.Background(),
		0,
		&storageMock{},
		&serfMock{},
		&firmwareStorageMock{},
		&rfeMock{},
		newRTPFWMock(),
		&dummyRTPDB{},
		datacalculator,
		fakeGateChecker,
		&scubaMock{},
		"dummy_scuba1",
		&scubaMock{},
		time.Hour,
		time.Hour,
		10,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, controller)
	defer func() {
		assert.NoError(t, controller.Close())
	}()

	analyzers := []afas.AnalyzerInput{
		{
			// do not initialise anything
			PSPSignature: &afas.PSPSignatureInput{},
		},
	}

	report, err := controller.Analyze(context.Background(), &afas.HostInfo{
		AssetID: &[]int64{42}[0],
	}, nil, analyzers)
	require.NoError(t, err)
	require.NotNil(t, report)

	require.Len(t, report.Results, 1)
	require.NotNil(t, report.Results[0].GetAnalyzerOutcome().Err)
	require.Equal(t, afas.ErrorClass_InvalidInput, report.Results[0].GetAnalyzerOutcome().Err.ErrorClass)
}

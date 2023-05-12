package firmwarewand

import (
	"fmt"
	"sort"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/measurements"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/typeconv"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flowscompat"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// AnalyzeRequestBuilder is a helper function to create AnalyzeRequest
type AnalyzeRequestBuilder struct {
	putArtifactsToPos map[objhash.ObjHash]int32
	request           afas.AnalyzeRequest
}

// NewAnalyzeRequestBuilder creates NewAnalyzeRequestBuilder object
func NewAnalyzeRequestBuilder() *AnalyzeRequestBuilder {
	return &AnalyzeRequestBuilder{
		putArtifactsToPos: make(map[objhash.ObjHash]int32),
	}
}

// GetThrift returns AnalyzeRequest used for communication with AFAS over thrift
func (req *AnalyzeRequestBuilder) GetThrift() *afas.AnalyzeRequest {
	return &req.request
}

// AddLocalHostInfo adds information about the local host
func (req *AnalyzeRequestBuilder) AddLocalHostInfo() error {
	hostInfo, err := localHostInfo()
	if err != nil {
		return err
	}
	req.request.HostInfo = hostInfo
	return nil
}

// AddDiffMeasuredBootInput populates AnalyzeRequest with input for DiffMeasuredBoot analyzer
func (req *AnalyzeRequestBuilder) AddDiffMeasuredBootInput(
	firmwareVersion, firmwareDate string,
	originalFirmwareImage *afas.FirmwareImage,
	actualFirmwareImage afas.FirmwareImage,
	actualRegisters registers.Registers,
	tpmDevice tpmdetection.Type,
	eventLog *tpmeventlog.TPMEventLog,
	actualPCR0 []byte,
) error {
	if err := checkFirmwareVersionDate(firmwareVersion, firmwareDate); err != nil {
		return err
	}
	if originalFirmwareImage != nil {
		if err := checkFirmwareImageIsCorrectEnum(*originalFirmwareImage, "originalFirmwareImage"); err != nil {
			return err
		}
	}
	if err := checkFirmwareImageIsCorrectEnum(actualFirmwareImage, "actualFirmwareImage"); err != nil {
		return err
	}

	thriftRegisters, err := typeconv.ToThriftRegisters(actualRegisters)
	if err != nil {
		return fmt.Errorf("failed to convert registers to thrift format: %w", err)
	}
	sort.Slice(thriftRegisters, func(i, j int) bool {
		return thriftRegisters[i].GetID() < thriftRegisters[j].GetID()
	})

	thriftTPM, err := typeconv.ToThriftTPMType(tpmDevice)
	if err != nil {
		return fmt.Errorf("failed to convert TPM type to thrift format: %w", err)
	}

	thriftEventlog := typeconv.ToThriftTPMEventLog(eventLog)

	var input afas.DiffMeasuredBootInput
	switch {
	case originalFirmwareImage != nil:
		firmwareImageArtifact := &afas.Artifact{
			FwImage: originalFirmwareImage,
		}
		idx := req.addArtifact(firmwareImageArtifact)
		input.OriginalFirmwareImage = &idx
	case len(firmwareVersion) > 0:
		firmwareVersionArtifact := &afas.Artifact{
			FwImage: &afas.FirmwareImage{
				FwVersion: &afas.FirmwareVersion{
					Version: firmwareVersion,
					Date:    firmwareDate,
				},
			},
		}
		idx := req.addArtifact(firmwareVersionArtifact)
		input.OriginalFirmwareImage = &idx
	}

	{
		firmwareImageArtifact := &afas.Artifact{
			FwImage: &actualFirmwareImage,
		}
		idx := req.addArtifact(firmwareImageArtifact)
		input.ActualFirmwareImage = idx
	}

	if len(thriftRegisters) > 0 {
		registersArtifact := &afas.Artifact{
			StatusRegisters: thriftRegisters,
		}
		idx := req.addArtifact(registersArtifact)
		input.StatusRegisters = &idx
	}

	if thriftTPM != afas.TPMType_UNKNOWN {
		tpmTypeArtifact := &afas.Artifact{
			TPMDevice: &thriftTPM,
		}
		idx := req.addArtifact(tpmTypeArtifact)
		input.TPMDevice = &idx
	}

	if thriftEventlog != nil {
		eventlogArtifact := &afas.Artifact{
			TPMEventLog: thriftEventlog,
		}
		idx := req.addArtifact(eventlogArtifact)
		input.TPMEventLog = &idx
	}

	if len(actualPCR0) > 0 {
		pcrArtifact := &afas.Artifact{
			Pcr: &afas.PCR{
				Value: actualPCR0,
				Index: 0,
			},
		}
		idx := req.addArtifact(pcrArtifact)
		input.ActualPCR0 = &idx
	}

	req.request.Analyzers = append(req.request.Analyzers, &afas.AnalyzerInput{
		DiffMeasuredBoot: &input,
	})
	return nil
}

// AddIntelACMInput populates AnalyzeRequest with input for IntelACM analyzer
func (req *AnalyzeRequestBuilder) AddIntelACMInput(
	firmwareVersion, firmwareDate string,
	originalFirmwareImage *afas.FirmwareImage,
	actualFirmwareImage afas.FirmwareImage,
) error {
	if err := checkFirmwareVersionDate(firmwareVersion, firmwareDate); err != nil {
		return err
	}
	if originalFirmwareImage != nil {
		if err := checkFirmwareImageIsCorrectEnum(*originalFirmwareImage, "originalFirmwareImage"); err != nil {
			return err
		}
	}
	if err := checkFirmwareImageIsCorrectEnum(actualFirmwareImage, "actualFirmwareImage"); err != nil {
		return err
	}
	if len(firmwareVersion) == 0 && originalFirmwareImage == nil {
		return fmt.Errorf("either firmware version/date or originalFirmwareImage should be provided (or both)")
	}

	var input afas.IntelACMInput
	switch {
	case originalFirmwareImage != nil:
		firmwareImageArtifact := &afas.Artifact{
			FwImage: originalFirmwareImage,
		}
		idx := req.addArtifact(firmwareImageArtifact)
		input.OriginalFirmwareImage = &idx
	case len(firmwareVersion) > 0:
		firmwareVersionArtifact := &afas.Artifact{
			FwImage: &afas.FirmwareImage{
				FwVersion: &afas.FirmwareVersion{
					Version: firmwareVersion,
					Date:    firmwareDate,
				},
			},
		}
		idx := req.addArtifact(firmwareVersionArtifact)
		input.OriginalFirmwareImage = &idx
	}

	{
		firmwareImageArtifact := &afas.Artifact{
			FwImage: &actualFirmwareImage,
		}
		idx := req.addArtifact(firmwareImageArtifact)
		input.ActualFirmwareImage = idx
	}

	req.request.Analyzers = append(req.request.Analyzers, &afas.AnalyzerInput{
		IntelACM: &input,
	})
	return nil
}

// AddReproducePCRInput populates AnalyzeRequest with input for ReproducePCR analyzer
func (req *AnalyzeRequestBuilder) AddReproducePCRInput(
	firmwareVersion, firmwareDate string,
	originalFirmwareImage *afas.FirmwareImage,
	actualFirmwareImage afas.FirmwareImage,
	actualRegisters registers.Registers,
	tpmDevice tpmdetection.Type,
	eventLog *tpmeventlog.TPMEventLog,
	flow pcr.Flow,
	expectedPCR0 []byte,
) error {
	if err := checkFirmwareVersionDate(firmwareVersion, firmwareDate); err != nil {
		return err
	}
	if originalFirmwareImage != nil {
		if err := checkFirmwareImageIsCorrectEnum(*originalFirmwareImage, "originalFirmwareImage"); err != nil {
			return err
		}
	}
	if err := checkFirmwareImageIsCorrectEnum(actualFirmwareImage, "actualFirmwareImage"); err != nil {
		return err
	}
	if len(expectedPCR0) == 0 {
		return fmt.Errorf("expectedPC0 is not provided")
	}

	thriftRegisters, err := typeconv.ToThriftRegisters(actualRegisters)
	if err != nil {
		return fmt.Errorf("failed to convert registers to thrift format: %w", err)
	}
	sort.Slice(thriftRegisters, func(i, j int) bool {
		return thriftRegisters[i].GetID() < thriftRegisters[j].GetID()
	})

	thriftTPM, err := typeconv.ToThriftTPMType(tpmDevice)
	if err != nil {
		return fmt.Errorf("failed to convert TPM type to thrift format: %w", err)
	}

	thriftEventlog := typeconv.ToThriftTPMEventLog(eventLog)

	thriftPCRFlow, err := typeconv.ToThriftFlow(flowscompat.FromOld(flow))
	if err != nil {
		return fmt.Errorf("failed to convert measurements flow to thrift format: %w", err)
	}

	var input afas.ReproducePCRInput
	switch {
	case originalFirmwareImage != nil:
		firmwareImageArtifact := &afas.Artifact{
			FwImage: originalFirmwareImage,
		}
		idx := req.addArtifact(firmwareImageArtifact)
		input.OriginalFirmwareImage = &idx
	case len(firmwareVersion) > 0:
		firmwareVersionArtifact := &afas.Artifact{
			FwImage: &afas.FirmwareImage{
				FwVersion: &afas.FirmwareVersion{
					Version: firmwareVersion,
					Date:    firmwareDate,
				},
			},
		}
		idx := req.addArtifact(firmwareVersionArtifact)
		input.OriginalFirmwareImage = &idx
	}

	{
		firmwareImageArtifact := &afas.Artifact{
			FwImage: &actualFirmwareImage,
		}
		idx := req.addArtifact(firmwareImageArtifact)
		input.ActualFirmwareImage = idx
	}

	if len(thriftRegisters) > 0 {
		registersArtifact := &afas.Artifact{
			StatusRegisters: thriftRegisters,
		}
		idx := req.addArtifact(registersArtifact)
		input.StatusRegisters = &idx
	}

	if thriftTPM != afas.TPMType_UNKNOWN {
		tpmTypeArtifact := &afas.Artifact{
			TPMDevice: &thriftTPM,
		}
		idx := req.addArtifact(tpmTypeArtifact)
		input.TPMDevice = &idx
	}

	if thriftEventlog != nil {
		eventlogArtifact := &afas.Artifact{
			TPMEventLog: thriftEventlog,
		}
		idx := req.addArtifact(eventlogArtifact)
		input.TPMEventLog = &idx
	}

	if len(expectedPCR0) > 0 {
		pcrArtifact := &afas.Artifact{
			Pcr: &afas.PCR{
				Value: expectedPCR0,
				Index: 0,
			},
		}
		idx := req.addArtifact(pcrArtifact)
		input.ExpectedPCR = idx
	}

	if thriftPCRFlow != measurements.Flow_AUTO {
		pcrArtifact := &afas.Artifact{
			MeasurementsFlow: &thriftPCRFlow,
		}
		idx := req.addArtifact(pcrArtifact)
		input.MeasurementsFlow = &idx
	}

	req.request.Analyzers = append(req.request.Analyzers, &afas.AnalyzerInput{
		ReproducePCR: &input,
	})
	return nil
}

// AddPSPSignatureInput populates AnalyzeRequest with input for PSPSignature analyzer
func (req *AnalyzeRequestBuilder) AddPSPSignatureInput(
	actualFirmwareImage *afas.FirmwareImage,
) error {
	if actualFirmwareImage == nil {
		return fmt.Errorf("either firmware version/date or actualFirmwareImage should be provided (or both)")
	}
	if actualFirmwareImage != nil {
		if err := checkFirmwareImageIsCorrectEnum(*actualFirmwareImage, "actualFirmwareImage"); err != nil {
			return err
		}
	}
	var input afas.PSPSignatureInput
	idx := req.addArtifact(&afas.Artifact{
		FwImage: actualFirmwareImage,
	})
	input.ActualFirmwareImage = idx
	req.request.Analyzers = append(req.request.Analyzers, &afas.AnalyzerInput{
		PSPSignature: &input,
	})
	return nil
}

// AddBIOSRTMVolumeInput populates AnalyzeRequest with input for PSPSignature analyzer
func (req *AnalyzeRequestBuilder) AddBIOSRTMVolumeInput(
	actualFirmwareImage *afas.FirmwareImage,
) error {
	if actualFirmwareImage == nil {
		return fmt.Errorf("either firmware version/date or actualFirmwareImage should be provided (or both)")
	}
	if actualFirmwareImage != nil {
		if err := checkFirmwareImageIsCorrectEnum(*actualFirmwareImage, "actualFirmwareImage"); err != nil {
			return err
		}
	}
	var input afas.BIOSRTMVolumeInput
	idx := req.addArtifact(&afas.Artifact{
		FwImage: actualFirmwareImage,
	})
	input.ActualFirmwareImage = idx
	req.request.Analyzers = append(req.request.Analyzers, &afas.AnalyzerInput{
		BIOSRTMVolume: &input,
	})
	return nil
}

// AddAPCBSecurityTokensInput populates AnalyzeRequest with input for APCBSecurityTokens analyzer
func (req *AnalyzeRequestBuilder) AddAPCBSecurityTokensInput(
	actualFirmwareImage *afas.FirmwareImage,
) error {
	if actualFirmwareImage == nil {
		return fmt.Errorf("either firmware version/date or actualFirmwareImage should be provided (or both)")
	}
	if actualFirmwareImage != nil {
		if err := checkFirmwareImageIsCorrectEnum(*actualFirmwareImage, "actualFirmwareImage"); err != nil {
			return err
		}
	}
	var input afas.APCBSecurityTokensInput
	idx := req.addArtifact(&afas.Artifact{
		FwImage: actualFirmwareImage,
	})
	input.ActualFirmwareImage = idx
	req.request.Analyzers = append(req.request.Analyzers, &afas.AnalyzerInput{
		APCBSecurityTokens: &input,
	})
	return nil
}

func (req *AnalyzeRequestBuilder) addArtifact(art *afas.Artifact) int32 {
	artifactHash := objhash.MustBuild(art)
	idx, found := req.putArtifactsToPos[artifactHash]
	if found {
		return idx
	}

	idx = int32(len(req.request.Artifacts))
	req.request.Artifacts = append(req.request.Artifacts, art)
	req.putArtifactsToPos[artifactHash] = idx
	return idx
}

func checkFirmwareVersionDate(firmwareVersion, firmwareDate string) error {
	if (len(firmwareVersion) > 0) != (len(firmwareDate) > 0) {
		return fmt.Errorf("both firmware version and date should be specified or not")
	}
	return nil
}

func checkFirmwareImageIsCorrectEnum(image afas.FirmwareImage, name string) error {
	if image.CountSetFieldsFirmwareImage() != 1 {
		return fmt.Errorf("exactly one field should be set in %s, found: %d", name, image.CountSetFieldsFirmwareImage())
	}
	return nil
}

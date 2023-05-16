package analyzerinput

import (
	"context"
	"fmt"
	"sync"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/apcbsectokens"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/biosrtmvolume"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/pspsignature"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/reproducepcr"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flowscompat"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"

	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// NewDiffMeasuredBootInput constructs input needed for DiffMeasuredBoot analyzer
func NewDiffMeasuredBootInput(
	ctx context.Context,
	artifacts ArtifactsAccessor,
	input afas.DiffMeasuredBootInput,
) (analysis.Input, error) {
	log := logger.FromCtx(ctx)
	actualFirmware, originalFirmware, err := getFirmwarePair(ctx, artifacts, input.ActualFirmwareImage, input.OriginalFirmwareImage)
	if err != nil {
		return nil, fmt.Errorf("unable to get the firmware pair: %w", err)
	}
	regs, err := getStatusRegisters(ctx, false, &input, artifacts)
	if err != nil {
		return nil, err
	}
	tpm, err := getTPMDevice(ctx, false, &input, artifacts)
	if err != nil {
		return nil, err
	}
	eventlog, err := getTPMEventlog(ctx, false, &input, artifacts)
	if err != nil {
		return nil, err
	}

	var actualPCR0 []byte
	if input.IsSetActualPCR0() {
		var pcrIdx uint32
		actualPCR0, pcrIdx, err = artifacts.GetPCR(ctx, int(input.GetActualPCR0()))
		if err != nil {
			log.Errorf("Failed to get actual PCR0 using artifact %d, err: %v", input.GetTPMEventLog(), err)
			return nil, err
		}
		if pcrIdx != 0 {
			err = fmt.Errorf("unexpected PCR index: %d != 0", pcrIdx)
			log.Errorf("%v", err)
			return nil, err
		}
	}

	result, err := diffmeasuredboot.NewExecutorInput(
		originalFirmware,
		actualFirmware,
		regs,
		tpm,
		eventlog,
		actualPCR0,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// NewReproducePCRInput constructs input needed for ReproducePCR analyzer
func NewReproducePCRInput(
	ctx context.Context,
	artifacts ArtifactsAccessor,
	input afas.ReproducePCRInput,
) (analysis.Input, error) {
	log := logger.FromCtx(ctx)
	actualFirmware, originalFirmware, err := getFirmwarePair(ctx, artifacts, input.ActualFirmwareImage, input.OriginalFirmwareImage)
	if err != nil {
		return nil, fmt.Errorf("unable to get the firmware pair: %w", err)
	}
	regs, err := getStatusRegisters(ctx, false, &input, artifacts)
	if err != nil {
		return nil, err
	}
	tpm, err := getTPMDevice(ctx, false, &input, artifacts)
	if err != nil {
		return nil, err
	}
	eventlog, err := getTPMEventlog(ctx, false, &input, artifacts)
	if err != nil {
		return nil, err
	}
	flow, err := getMeasurementsFlow(ctx, false, &input, artifacts)
	if err != nil {
		return nil, err
	}
	expectedPCR0, pcrIdx, err := artifacts.GetPCR(ctx, int(input.GetExpectedPCR()))
	if err != nil {
		log.Errorf("Failed to get actual PCR0 using artifact %d, err: %v", input.GetTPMEventLog(), err)
		return nil, err
	}
	if pcrIdx != 0 {
		err = fmt.Errorf("unexpected PCR index: %d != 0", pcrIdx)
		log.Errorf("%v", err)
		return nil, err
	}

	result, err := reproducepcr.NewExecutorInput(
		originalFirmware,
		actualFirmware,
		regs,
		tpm,
		eventlog,
		flowscompat.ToOld(bootflowtypes.Flow(flow)),
		expectedPCR0,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func getFirmwarePair(
	ctx context.Context,
	artifacts ArtifactsAccessor,
	actualFirmwareIdx int32,
	originalFirmwareIdx *int32,
) (actualFirmware analysis.Blob, originalFirmware analysis.Blob, err error) {
	span, ctx := tracer.StartChildSpanFromCtx(ctx, "getFirmwarePair")
	defer span.Finish()
	var (
		actualFirmwareErr, originalFirmwareErr error
		wg                                     sync.WaitGroup
	)
	if originalFirmwareIdx != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			span, ctx := tracer.StartChildSpanFromCtx(ctx, "getFirmwarePair-original")
			defer span.Finish()
			originalFirmware, originalFirmwareErr = artifacts.GetFirmware(ctx, int(*originalFirmwareIdx))
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		span, ctx := tracer.StartChildSpanFromCtx(ctx, "getFirmwarePair-actual")
		defer span.Finish()
		actualFirmware, actualFirmwareErr = artifacts.GetFirmware(ctx, int(actualFirmwareIdx))
	}()
	wg.Wait()

	if actualFirmwareErr != nil {
		// TODO: Do not cancel analysis because of these errors, it still can provide useful info.
		return nil, nil, fmt.Errorf("unable to get the actual firmware image: %w", actualFirmwareErr)
	}
	if originalFirmwareErr != nil {
		// TODO: Do not cancel analysis because of these errors, it still can provide useful info.
		return nil, nil, fmt.Errorf("unable to get the original firmware image: %w", originalFirmwareErr)
	}
	return
}

// NewIntelACMInput constructs input needed for IntelACM analyzer
func NewIntelACMInput(
	ctx context.Context,
	artifacts ArtifactsAccessor,
	input afas.IntelACMInput,
) (analysis.Input, error) {
	actualFirmware, originalFirmware, err := getFirmwarePair(ctx, artifacts, input.ActualFirmwareImage, input.OriginalFirmwareImage)
	if err != nil {
		return nil, fmt.Errorf("unable to get the firmware pair: %w", err)
	}
	result, err := intelacm.NewExecutorInput(
		originalFirmware,
		actualFirmware,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// NewPSPSignatureInput constructs input needed for PSPSignature analyzer
func NewPSPSignatureInput(
	ctx context.Context,
	artifacts ArtifactsAccessor,
	input afas.PSPSignatureInput,
) (analysis.Input, error) {
	actualFirmware, err := artifacts.GetFirmware(ctx, int(input.ActualFirmwareImage))
	if err != nil {
		// TODO: Do not cancel analysis because of these errors, it still can provide useful info.
		return nil, fmt.Errorf("unable to get the original firmware image ID: %w", err)
	}

	result, err := pspsignature.NewExecutorInput(
		actualFirmware,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// NewBIOSRTMVolumeInput constructs input needed for BIOSRTMVolume analyzer
func NewBIOSRTMVolumeInput(
	ctx context.Context,
	artifacts ArtifactsAccessor,
	input afas.BIOSRTMVolumeInput,
) (analysis.Input, error) {
	actualFirmware, err := artifacts.GetFirmware(ctx, int(input.ActualFirmwareImage))
	if err != nil {
		// TODO: Do not cancel analysis because of these errors, it still can provide useful info.
		return nil, fmt.Errorf("unable to get the original firmware image ID: %w", err)
	}

	result, err := biosrtmvolume.NewExecutorInput(
		actualFirmware,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// NewAPCBSecurityTokensInput constructs input needed for APCBSecurityTokens analyzer
func NewAPCBSecurityTokensInput(
	ctx context.Context,
	artifacts ArtifactsAccessor,
	input afas.APCBSecurityTokensInput,
) (analysis.Input, error) {
	actualFirmware, err := artifacts.GetFirmware(ctx, int(input.ActualFirmwareImage))
	if err != nil {
		// TODO: Do not cancel analysis because of these errors, it still can provide useful info.
		return nil, fmt.Errorf("unable to get the original firmware image ID: %w", err)
	}

	result, err := apcbsectokens.NewExecutorInput(
		actualFirmware,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

type registersArtifactsIndicies interface {
	IsSetStatusRegisters() bool
	GetStatusRegisters() int32
}

func getStatusRegisters(
	ctx context.Context,
	verifyExists bool,
	input registersArtifactsIndicies,
	artifacts ArtifactsAccessor,
) (registers.Registers, error) {
	if !input.IsSetStatusRegisters() {
		if verifyExists {
			return nil, fmt.Errorf("no artifcat describes status registers image")
		}
		return nil, nil
	}
	regs, err := artifacts.GetRegisters(ctx, int(input.GetStatusRegisters()))
	if err != nil {
		return nil, fmt.Errorf("failed to get registers using artifact '%d': '%w'", input.GetStatusRegisters(), err)
	}
	return regs, nil
}

type tpmArtifactsIndicies interface {
	IsSetTPMDevice() bool
	GetTPMDevice() int32
}

func getTPMDevice(
	ctx context.Context,
	verifyExists bool,
	input tpmArtifactsIndicies,
	artifacts ArtifactsAccessor,
) (tpmdetection.Type, error) {
	if !input.IsSetTPMDevice() {
		if verifyExists {
			return tpmdetection.TypeNoTPM, fmt.Errorf("no artifact describes TPM device")
		}
		return tpmdetection.TypeNoTPM, nil
	}
	tpm, err := artifacts.GetTPMDevice(ctx, int(input.GetTPMDevice()))
	if err != nil {
		return tpmdetection.TypeNoTPM, fmt.Errorf("failed to get TPM device using artifact '%d': '%w'", input.GetTPMDevice(), err)
	}
	return tpm, nil
}

type tpmEventlogArtifactsIndicies interface {
	IsSetTPMEventLog() bool
	GetTPMEventLog() int32
}

func getTPMEventlog(
	ctx context.Context,
	verifyExists bool,
	input tpmEventlogArtifactsIndicies,
	artifacts ArtifactsAccessor,
) (*tpmeventlog.TPMEventLog, error) {
	if !input.IsSetTPMEventLog() {
		if verifyExists {
			return nil, fmt.Errorf("no artifact describes TPM device")
		}
		return nil, nil
	}
	eventlog, err := artifacts.GetTPMEventLog(ctx, int(input.GetTPMEventLog()))
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM eventlog using artifact '%d': '%w'", input.GetTPMEventLog(), err)
	}
	return eventlog, nil
}

type measurementsFlowArtifactsIndicies interface {
	IsSetMeasurementsFlow() bool
	GetMeasurementsFlow() int32
}

func getMeasurementsFlow(
	ctx context.Context,
	verifyExists bool,
	input measurementsFlowArtifactsIndicies,
	artifacts ArtifactsAccessor,
) (types.BootFlow, error) {
	if !input.IsSetMeasurementsFlow() {
		if verifyExists {
			return types.BootFlow(flows.Root), fmt.Errorf("no artifact describes measurements flow")
		}
		return types.BootFlow(flows.Root), nil
	}
	flow, err := artifacts.GetMeasurementsFlow(ctx, int(input.GetMeasurementsFlow()))
	if err != nil {
		return types.BootFlow(flows.Root), fmt.Errorf("failed to get TPM eventlog using artifact '%d': '%w'", input.GetMeasurementsFlow(), err)
	}
	return flow, nil
}

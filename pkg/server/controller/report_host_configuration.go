package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/typeconv"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/measurements"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/go-tpm/tpm2"
)

// HostConfigurationPCRs contains information about calculated PCR0 values
type HostConfigurationPCRs struct {
	PCR0SHA1   []byte
	PCR0SHA256 []byte
}

// ReportHostConfiguration calculates and puts a correct PCR0 value for specified host environment into RTP firmwate table
func (ctrl *Controller) ReportHostConfiguration(
	ctx context.Context,
	_hostInfo *afas.HostInfo,
	firmwareVersion, firmwareDate string,
	tpmDevice tpmdetection.Type,
	statusRegisters []*afas.StatusRegister,
	eventLog *tpmeventlog.TPMEventLog,
	hostPCR0 []byte,
) (HostConfigurationPCRs, error) {
	if tpmDevice != tpmdetection.TypeTPM20 {
		return HostConfigurationPCRs{}, fmt.Errorf("TPM %s is not supported", tpmDevice)
	}
	log := logger.FromCtx(ctx)
	sort.Slice(statusRegisters, func(i, j int) bool {
		return statusRegisters[i].Id < statusRegisters[j].Id
	})

	if _hostInfo == nil {
		return HostConfigurationPCRs{}, fmt.Errorf("internal error, should never happen: host is undefined")
	}
	hostInfo := *_hostInfo // copy

	serfDevice, isVerified := getClientSeRFDevice(ctx, ctrl.SeRF, &hostInfo)
	if serfDevice != nil {
		enrichHostInfo(ctx, serfDevice, isVerified, &hostInfo)
	}
	evaluationStatus := getRTPEvaluationStatus(ctx, serfDevice)
	log.Infof("Device info: '%s, eval status: %s", hostInfo.String(), evaluationStatus)

	cacheKey := getReportHostConfigurationCacheKey(
		firmwareVersion, firmwareDate, evaluationStatus,
		tpmDevice,
		statusRegisters,
		eventLog,
		hostPCR0,
	)
	l := ctrl.ReportHostConfigLock.Lock(cacheKey)
	defer l.Unlock()
	if l.UserData != nil {
		resultPCRs := l.UserData.(HostConfigurationPCRs)
		ctrl.logHostConfigurationToScuba(ctx, hostInfo, firmwareVersion, firmwareDate, statusRegisters,
			tpmDevice, eventLog, hostPCR0, resultPCRs.PCR0SHA1, resultPCRs.PCR0SHA256)
		return resultPCRs, nil
	}

	cachedItem, found := ctrl.ReportHostConfigCache.Get(cacheKey)
	if found {
		log.Debugf("return cached item from ReportHostConfigCache")
		resultPCRs := cachedItem.(HostConfigurationPCRs)
		ctrl.logHostConfigurationToScuba(ctx, hostInfo, firmwareVersion, firmwareDate, statusRegisters,
			tpmDevice, eventLog, hostPCR0, resultPCRs.PCR0SHA1, resultPCRs.PCR0SHA256)
		return resultPCRs, nil
	}

	var reported bool
	reportToScuba := func(resultPCR0SHA1, resultPCR0SHA256 []byte) {
		if reported {
			return
		}
		reported = true
		ctrl.logHostConfigurationToScuba(ctx, hostInfo, firmwareVersion, firmwareDate, statusRegisters,
			tpmDevice, eventLog, hostPCR0, resultPCR0SHA1, resultPCR0SHA256)
	}
	defer reportToScuba(nil, nil)

	modelFamilyID := ctrl.getModelFamilyID(ctx, &hostInfo)

	firmware, err := asd //getRTPFirmware(ctx, ctrl.rtpfw, firmwareVersion, firmwareDate, modelFamilyID, evaluationStatus, types.CachingPolicyDefault)
	if err != nil {
		return HostConfigurationPCRs{}, NewErrFetchOrigFirmware(firmwareVersion, firmwareDate, err)
	}
	evaluationStatus = firmware.Metadata.EvaluationStatus
	log.Infof("Got firmware with evaluation status: '%s'", evaluationStatus)

	regs, err := typeconv.FromThriftRegisters(statusRegisters)
	if err != nil {
		log.Errorf("failed to convert registers: %v", err)
	}

	uefi, err := ctrl.parseUEFI(firmware.ImageFile.Data)
	if err != nil {
		return HostConfigurationPCRs{}, NewErrParseOrigFirmware(firmwareVersion, firmwareDate, err)
	}

	fixedRegisters, issues, err := measurements.GetFixedHostConfiguration(ctx, uefi, 0, uefi.Buf(), regs, eventLog, hostPCR0)
	if len(issues) != 0 {
		log.Warnf("got issues from GetFixedHostConfiguration: %v", issues)
	}
	if err != nil {
		// this could be ok due to incorrect information from the host such as firmware bitflips
		err = fmt.Errorf("failed to get fixed host configuration, err: %w", err)
		log.Errorf("%v", err)
		return HostConfigurationPCRs{}, NewErrInvalidHostConfiguration(err)
	}

	// TODO: refactor the code below:
	bootResult := measurements.SimulateBootProcess(
		ctx,
		biosimage.NewFromParsed(uefi),
		fixedRegisters,
		flows.Root,
	)
	if err := bootResult.Log.Error(); err != nil {
		return HostConfigurationPCRs{}, NewErrInvalidHostConfiguration(fmt.Errorf("failed to detect measurements flow, err: %w", err))
	}
	resultFlow := measurements.ExtractResultingBootFlow(bootResult.Log)

	resultPCRSHA1, err := measurements.CalculatePCR0(ctx, uefi, resultFlow, fixedRegisters, tpm2.AlgSHA1)
	if err != nil {
		log.Errorf("failed to calculate PCR0 for SHA1, flow: '%s', firmware: '%s'/'%s'", resultFlow, firmwareVersion, firmwareDate)
	}
	resultPCRSHA256, err := measurements.CalculatePCR0(ctx, uefi, resultFlow, fixedRegisters, tpm2.AlgSHA256)
	if err != nil {
		log.Errorf("failed to calculate PCR0 for SHA256, flow: '%s', firmware: '%s'/'%s'", resultFlow, firmwareVersion, firmwareDate)
	}

	reportToScuba(resultPCRSHA1, resultPCRSHA256)
	if ctrl.checkReportConfigGate(hostInfo) {
		log.Debugf("passed sysprov/gating/ramdisk_attestation_report_config, inserting pcr0")
		ctrl.insertPCR0(ctx, firmware, firmwareVersion, firmwareDate, modelFamilyID, evaluationStatus, flows.ToOld(resultFlow), regs, resultPCRSHA1, resultPCRSHA256)
	} else {
		log.Debugf("did not pass sysprov/gating/ramdisk_attestation_report_config, not inserting pcr0")
	}

	ctrl.launchAsync(ctx, func(ctx context.Context) {
		log := logger.FromCtx(ctx)
		hashStable, err := types.NewImageStableHashFromImage(firmware.ImageFile.GetData())
		if err != nil {
			log.Errorf("Unable to calculate the stable hash for the image: %v", err)
		}

		metadata := models.NewImageMetadata(
			firmware.ImageFile.GetData(),
			firmwareVersion,
			firmwareDate,
			firmware.ImageFile.GetName(),
		)
		err = ctrl.Storage.Insert(ctx, metadata, firmware.ImageFile.GetData())
		if err != nil && !errors.As(err, &storage.ErrAlreadyExists{}) {
			log.Errorf("Failed to save image: '%X', err: '%v'", metadata.ImageID, err)
			return
		}

		reproducedPCRs, err := models.NewReproducedPCRs(
			hashStable,
			fixedRegisters,
			tpmDevice,
			resultPCRSHA1,
			resultPCRSHA256,
		)
		if err != nil {
			log.Errorf("Failed to construct ReproducedPCRs object: '%v'", err)
			return
		}

		if err := ctrl.Storage.UpsertReproducedPCRs(ctx, reproducedPCRs); err != nil {
			log.Errorf("Failed to upsert ReproducedPCRs %#+v: '%v'", reproducedPCRs, err)
			return
		}
		log.Infof("Added information about reproduced PCRs, ImageHashStable: '0x%X', PCR0 SHA1: '0x%X', PCR0 SHA256: '0x%X'",
			hashStable,
			resultPCRSHA1,
			resultPCRSHA256,
		)
	})

	result := HostConfigurationPCRs{
		PCR0SHA1:   resultPCRSHA1,
		PCR0SHA256: resultPCRSHA256,
	}
	ctrl.ReportHostConfigCache.Add(cacheKey, result)

	l.UserData = result
	return result, nil
}

func (ctrl *Controller) checkReportConfigGate(hostInfo afas.HostInfo) bool {
	const gate = "ramdisk_attestation_report_config"

	if hostInfo.AssetID != nil {
		return ctrl.gateChecker.CheckAssetID(gate, *hostInfo.AssetID)
	}
	return ctrl.gateChecker.CheckHostname(gate, *hostInfo.Hostname)
}

func (ctrl *Controller) logHostConfigurationToScuba(ctx context.Context, hostInfo afas.HostInfo,
	firmwareVersion, firmwareDate string, statusRegisters []*afas.StatusRegister,
	tpmDevice tpmdetection.Type, eventLog *tpmeventlog.TPMEventLog, hostPCR0 []byte,
	resultPCR0SHA1, resultPCR0SHA256 []byte,
) {
	log := logger.FromCtx(ctx)
	log.Infof("result PCR0 value sha1: '0x%X', sha256: '0x%X'", resultPCR0SHA1, resultPCR0SHA256)

	var assetID int32
	var hostname string
	var modelID int32

	// It is ok to get the information from client. We do it anyway
	if hostInfo.AssetID != nil {
		assetID = int32(*hostInfo.AssetID)
	}
	if hostInfo.Hostname != nil {
		hostname = *hostInfo.Hostname
	}
	if hostInfo.ModelID != nil {
		modelID = *hostInfo.ModelID
	}

	configurationReport := scubareport.NewHostConfiguration(
		assetID,
		hostname,
		modelID,
		firmwareVersion,
		firmwareDate,
		statusRegisters,
		tpmDevice,
		eventLog,
		hostPCR0,
		resultPCR0SHA1,
		resultPCR0SHA256,
	)
	log.Infof("Final configuration report: %v", configurationReport)
	if err := ctrl.hostConfigScuba.Log(configurationReport); err != nil {
		log.Errorf("failed to send logs to scuba: %v", err)
	}
}

func (ctrl *Controller) insertPCR0(
	ctx context.Context,
	firmware sdf, //rtpfw.Firmware,
	firmwareVersion, firmwareDate string,
	modelFamilyID *uint64,
	evaluationStatus sdf, // rtp.EvaluationStatus,
	resultFlow pcr.Flow, regs registers.Registers,
	resultPCRSHA1, resultPCRSHA256 []byte,
) {
	log := logger.FromCtx(ctx)
	txtDisabledPCR := firmware.Metadata.PCRValues.AnyByProperties(types.PropertyIntelTXT(false))
	if txtDisabledPCR == nil {
		log.Errorf("TXT disabled PCR is not found, insertion is skipped")
		return
	}
	props, err := types.PropertiesFromFlow(resultFlow, regs)
	if err != nil {
		log.Errorf("failed to get properties for flow: %v, registers: %v, insertion is skipped", resultFlow, regs)
		return
	}
	log.Infof("result properties: '%v'", props)

	var insertedPCRs sdf // rtpfw.PCRValues
	if len(resultPCRSHA1) > 0 {
		insertedPCRs = append(insertedPCRs, types.NewPCRValue(0, resultPCRSHA1, props...))
	}
	if len(resultPCRSHA256) > 0 {
		insertedPCRs = append(insertedPCRs, types.NewPCRValue(0, resultPCRSHA256, props...))
	}

	// If PCR0 value already exists we assume it was manually set, so do not
	// override the tags (therefore "false" as the last argument)
	err = ctrl.rtpfw.UpsertPCRs(ctx, txtDisabledPCR.Value, firmwareVersion, firmwareDate, modelFamilyID, evaluationStatus, insertedPCRs, false, types.PCRValidated)
	if err != nil {
		log.Errorf("failed to insert PCR0: %v", err)
		return
	}
	log.Infof("successfully inserted PCRs for firmware: '%s'/'%s'", firmwareVersion, firmwareDate)
}

func getReportHostConfigurationCacheKey(
	firmwareVersion, firmwareDate string,
	evaluationStatus sdf, //rtp.EvaluationStatus,
	tpmDevice tpmdetection.Type,
	statusRegisters []*afas.StatusRegister,
	eventLog *tpmeventlog.TPMEventLog,
	hostPCR0 []byte,
) objhash.ObjHash {
	if !sort.SliceIsSorted(statusRegisters, func(i, j int) bool {
		return statusRegisters[i].Id < statusRegisters[j].Id
	}) {
		panic("statusRegisters are not sorted")
	}

	return objhash.MustBuild(
		firmwareVersion,
		firmwareDate,
		evaluationStatus,
		tpmDevice,
		statusRegisters,
		eventLog,
		hostPCR0,
	)
}

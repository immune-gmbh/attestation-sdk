package firmwarewand

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/typeconv"
	xregisters "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/registers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/tpm"

	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/go-tpm/tpm2"
)

// ReportHostConfiguration calculates the expected value of PCR0 using local host configuration and trusted firmware image
func (fwwand *FirmwareWand) ReportHostConfiguration(
	eventLog *tpmeventlog.TPMEventLog,
	enforcedStatusRegisters registers.Registers,
	enforcedPCR0SHA1 []byte,
	enforcedFirmwareVersion, enforcedFirmwareDate string,
	enforcedTPMDevice tpmdetection.Type,
) ([][]byte, error) {
	l := logger.FromCtx(fwwand.context)

	usedTPMDevice := enforcedTPMDevice
	if usedTPMDevice == tpmdetection.TypeNoTPM {
		var err error
		usedTPMDevice, err = tpmdetection.Local()
		if err != nil {
			l.Errorf("failed to detect local TPM: %v", err)
			usedTPMDevice = tpmdetection.TypeNoTPM
		} else {
			l.Infof("Detected local TPM: %s", usedTPMDevice.String())
		}
	}

	var statusRegisters registers.Registers
	if enforcedStatusRegisters != nil {
		statusRegisters = enforcedStatusRegisters
	} else {
		var err error
		statusRegisters, err = xregisters.LocalRegisters()
		if err != nil {
			l.Debugf("unable to read some status registers: %v", err)
		}
		if statusRegisters == nil && err != nil {
			return nil, fmt.Errorf("unable to read status registers: %w", err)
		}
	}

	selectedTPMDevice, err := typeconv.ToThriftTPMType(usedTPMDevice)
	if err != nil {
		return nil, err
	}

	var usedFirmwareVersion string
	var usedFirmwareDate string
	if len(enforcedFirmwareVersion) > 0 && len(enforcedFirmwareDate) > 0 {
		usedFirmwareVersion = enforcedFirmwareVersion
		usedFirmwareDate = enforcedFirmwareDate
	} else {
		imageBytes, err := flashrom.Dump(fwwand.context, fwwand.flashromOptions...)
		if err != nil {
			return nil, ErrDumpFirmware{Err: err}
		}
		manifoldEntry := fwwand.FindImage(imageBytes)
		if manifoldEntry != nil {
			// See also the comment of originalFirmwareVariants
			if manifoldEntry.Version != nil && manifoldEntry.ReleaseDate != nil {
				usedFirmwareVersion = *manifoldEntry.Version
				usedFirmwareDate = *manifoldEntry.ReleaseDate
			}
		}

		firmwareOptions := detectLocalFirmware(l, manifoldEntry, imageBytes)
		if len(firmwareOptions) > 0 {
			usedFirmwareVersion = firmwareOptions[0].Version
			usedFirmwareDate = firmwareOptions[0].ReleaseDate
		}
	}

	if len(usedFirmwareVersion) == 0 || len(usedFirmwareDate) == 0 {
		return nil, fmt.Errorf("failed to detect firmware version")
	}
	l.Infof("will use the following firmware version/date: '%s'/'%s'", usedFirmwareVersion, usedFirmwareDate)

	fasStatusRegisters, err := typeconv.ToThriftRegisters(statusRegisters)
	if err != nil {
		// registers are critical, do not tolerate conversion failure
		return nil, fmt.Errorf("failed to convert registers: %w", err)
	}

	var usedPCR0Value []byte
	if len(enforcedPCR0SHA1) == 0 {
		usedPCR0Value, err = tpm.ReadPCRFromTPM(0, tpm2.AlgSHA1)
		// PCR is an optional value
		if err != nil {
			l.Warnf("unable to get the SHA1 PCR0 value from TPM: %v", err)
		}
	} else {
		usedPCR0Value = enforcedPCR0SHA1
	}

	hostInfo, err := localHostInfo()
	if err != nil {
		return nil, err
	}

	request := afas.ReportHostConfigurationRequest{
		FirmwareVersion:    usedFirmwareVersion,
		FirmwareDateString: usedFirmwareDate,
		TpmDevice:          &selectedTPMDevice,
		StatusRegisters:    fasStatusRegisters,
		TPMEventLog:        typeconv.ToThriftTPMEventLog(eventLog),
		PCRValue:           usedPCR0Value,
		HostInfo:           hostInfo,
	}

	l.Debugf("sending the request to firmware analyzer service...")
	response, err := fwwand.firmwareAnalyzer.ReportHostConfiguration(&request)
	if err != nil {
		l.Debugf("received an error from the firmware analyzer service: err == %T:%v", err)
		return nil, fmt.Errorf("firmware analyzer service returned error: %w", err)
	}
	if response == nil {
		l.Debugf("received a nil ReportHostConfigurationResult from the firmware analyzer service: err == %T:%v", err)
		return nil, fmt.Errorf("firmware analyzer service didn't return ReportHostConfigurationResult")
	}
	l.Debugf("received a response from the firmware analyzer service; err == %T:%v", *response)

	var pcrs [][]byte
	for _, pcr := range [][]byte{response.GetPCR0SHA1(), response.GetPCR0SHA256()} {
		if len(pcr) == 0 {
			continue
		}
		pcrs = append(pcrs, pcr)
	}
	return pcrs, nil
}

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
package validator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/dmidecode"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/measurements"
	xregisters "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/registers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/types"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/go-tpm/tpm2"
	"github.com/klauspost/cpuid/v2"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntbootpolicy"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/marcoguerri/go-tpm-tcti/abrmd"
)

const (
	// EventLogPath is the path used to extract TPM EventLog.
	EventLogPath = `/sys/kernel/security/tpm0/binary_bios_measurements`
)

// Firmware contains all information about a firmware image commonly
// needed in validators.
type Firmware struct {
	UEFI     *uefi.UEFI
	DMITable *dmidecode.DMITable
	Intel    *FirmwareIntelStructs
}

// FirmwareIntelStructs contains structures of a firmware image related to Intel CPUs.
type FirmwareIntelStructs struct {
	FIT fit.Table
	BPM *cbntbootpolicy.Manifest
	KM  *cbntkey.Manifest
}

// ValidationInfo is the prerequisites for any validation work.
type ValidationInfo struct {
	HostBooted                   bool
	SELs                         []types.SEL
	FirmwareCurrent              Firmware
	FirmwareExpected             Firmware
	FirmwareOriginal             Firmware
	FirmwareAlignToCurrentOffset uint64
	ExpectedBootResult           *bootengine.BootProcess
	ExpectedTPMState             *tpm.TPM
	StatusRegisters              registers.Registers
	EventLog                     *tpmeventlog.TPMEventLog
	PCR0Current                  map[tpm2.Algorithm][]byte
}

func parseBytes(b []byte) (Firmware, error) {
	var result Firmware
	var err error

	if result.UEFI, err = uefi.ParseUEFIFirmwareBytes(b); err != nil {
		return Firmware{}, fmt.Errorf("UEFI parsing error: %w", err)
	}

	fwInfo, err := types.NewFirmwareInfoProviderFromUEFI(result.UEFI)
	if err != nil {
		return Firmware{}, fmt.Errorf("could not extract firmware info: %w", err)
	}

	isIntel, err := types.IsArchitecture(fwInfo, cpuid.Intel)
	if err != nil {
		return Firmware{}, fmt.Errorf("could not determine if architecture is Intel: %w", err)
	}

	if isIntel {

		result.Intel = &FirmwareIntelStructs{}
		if result.Intel.FIT, err = fit.GetTable(b); err != nil {
			return Firmware{}, fmt.Errorf("FIT parsing error: %w", err)
		}

		if _, result.Intel.BPM, err = result.Intel.FIT.ParseBootPolicyManifest(b); err != nil {
			return Firmware{}, fmt.Errorf("boot policy manifest (BPM) parsing error: %w", err)
		}

		if _, result.Intel.KM, err = result.Intel.FIT.ParseKeyManifest(b); err != nil {
			return Firmware{}, fmt.Errorf("key manifest (KM) parsing error: %w", err)
		}
	}

	// TODO: consider using of dmidecode.DMITableFromFirmware instead (to avoid double-parsing of the image)
	if result.DMITable, err = dmidecode.DMITableFromFirmwareImage(fwInfo.Firmware().Buf()); err != nil {
		return Firmware{}, ErrParseDMITable{Err: err}
	}

	return result, nil
}

// TestCaseSetup represents the Setup method of a testcase
type TestCaseSetup interface {
	Setup(ctx context.Context, image []byte) error
}

// GetValidationInfo extracts ValidationInfo from the local machine.
func GetValidationInfo(
	ctx context.Context,
	t TestCaseSetup,
	origImage []byte,
	opts types.Options,
) (*ValidationInfo, error) {

	// TODO: Split the function.
	// TODO: Think may be we need dependency injections instead of options.
	optionsConfig := opts.Config()
	var err error
	result := &ValidationInfo{
		HostBooted:  !optionsConfig.HostNotBooted,
		SELs:        optionsConfig.ForceSELEvents,
		PCR0Current: map[tpm2.Algorithm][]byte{},
	}

	// Firmware images

	result.FirmwareOriginal, err = parseBytes(origImage)
	if err != nil {
		return nil, ErrOrigFirmware{Err: ErrParseFirmware{Err: err}}
	}

	// Reproducing the tampered image we expect on this machine.
	//
	// As input we get the original image, but to do the tests we also
	// need to know which tampered image we expect on this machine, so
	// we just reuse the same `Setup` to get the same image as we
	// expect to be already flashed.
	firmwareExpected := make([]byte, len(origImage))
	copy(firmwareExpected, origImage)
	if err = t.Setup(ctx, firmwareExpected); err != nil {
		return nil, ErrSetup{Err: err}
	}

	result.FirmwareExpected, err = parseBytes(firmwareExpected)
	if err != nil {
		return nil, ErrExpectedFirmware{Err: ErrParseFirmware{Err: err}}
	}

	// if optionsConfig.HostNotBooted {
	// 	return result, nil
	// }

	fwInfo, err := types.NewFirmwareInfoProvider(firmwareExpected)
	if err != nil {
		return nil, ErrExpectedFirmware{Err: fmt.Errorf("could not create firmware info provider from expected image: %w", err)}
	}

	isAmdPsb, err := types.SupportsFeature(fwInfo, types.AmdPSBMilan)
	if err != nil {
		return nil, ErrExpectedFirmware{Err: fmt.Errorf("could not determine if expected firmware supports AMD PSB: %w", err)}
	}

	// Status registers

	if regs := optionsConfig.ForceStatusRegisters; regs != nil {
		result.StatusRegisters = regs
	} else if !optionsConfig.HostNotBooted {
		result.StatusRegisters, err = xregisters.LocalRegisters()
		if result.StatusRegisters == nil && err != nil {
			// The && in the condition above is because
			//
			// GetMSRRegister might get not all registers and this is usually
			// fine. So the `err` is not nil, but msrRegisters are not empty and
			// this case is considered good. But if msrRegisters are empty, then
			// definitely something gone wrong (for example not enough permissions
			// to read the registers).
			//
			// TODO: modify GetMSRRegisters API to allow stricter error handling
			//       logic.
			return nil, ErrStatusRegisters{Err: err}
		}
	}

	// Dumping firmware

	if optionsConfig.UseFirmwareExpectedAsCurrent {
		result.FirmwareCurrent = result.FirmwareExpected
	} else if !optionsConfig.HostNotBooted {
		firmwareCurrent, err := flashrom.Dump(ctx, optionsConfig.FlashromOptions...)
		if err != nil {
			return nil, ErrDump{Err: err}
		}

		result.FirmwareCurrent, err = parseBytes(firmwareCurrent)
		if err != nil {
			return nil, ErrCurrentFirmware{Err: ErrParseFirmware{Err: err}}
		}

		result.FirmwareCurrent.DMITable, err = dmidecode.LocalDMITable()
		if err != nil {
			return nil, ErrLocalDMITable{Err: err}
		}
	}

	// TPM EventLog

	log := logger.FromCtx(ctx)

	if evs := optionsConfig.ForceEventLog; evs != nil {
		result.EventLog = &tpmeventlog.TPMEventLog{Events: evs}
	} else if !optionsConfig.HostNotBooted {
		result.EventLog, err = getEventLog(EventLogPath, log)
		if err != nil {
			return nil, ErrEventLog{Err: err, Path: EventLogPath}
		}
	}

	// Intel status registers hacks

	if result.FirmwareCurrent.Intel != nil {
		for idx, statusRegister := range result.StatusRegisters {
			switch statusRegister := statusRegister.(type) {
			case registers.ACMPolicyStatus:
				currentKMID := statusRegister.KMID()
				if currentKMID > result.FirmwareCurrent.Intel.KM.KMID {
					log.Warnf("KMID (%d != %d) is incremented due to Intel's bug https://premiersupport.intel.com/IPS/5003b00001aHC7N", currentKMID, result.FirmwareCurrent.Intel.KM.KMID)
					// KMID represents minor 4 bits of the ACM_POLICY_STATUS, this
					// is why it is corrupted first by these increments.
					//
					// KMID is a 4-bit value, therefore this way we can handle
					// corruptions up to 13 increments (because usually the KMID
					// value is 1-3).
					//
					// See also Intel document #575623 for more details about KMID
					// and ACM_POLICY_STATUS.
					statusRegister -= registers.ACMPolicyStatus(currentKMID - result.FirmwareCurrent.Intel.KM.KMID)
					result.StatusRegisters[idx] = statusRegister
				}
			}
		}
	}

	// Measurements

	// TODO: TPM1.2 does not support SHA256. Fix the code to support TPM1.2.
	algos := []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256}
	if isAmdPsb {
		// Milan has SHA256 only
		algos = []tpm2.Algorithm{tpm2.AlgSHA256}
	}

	{
		log := log
		if log.Level() > logger.LevelError {
			log = log.WithLevel(logger.LevelError)
		}
		ctx := logger.CtxWithLogger(ctx, log)

		bootResult := measurements.SimulateBootProcess(
			beltctx.WithField(ctx, "subroutine", "measurements.SimulateBootProcess"),
			biosimage.NewFromParsed(result.FirmwareExpected.UEFI),
			result.StatusRegisters,
			flows.Root,
		)
		if err := bootResult.Log.Error(); err != nil {
			return nil, ErrGetPCR0Measurements{Err: fmt.Errorf("unable to simulate boot process: %w", err)}
		}
		result.ExpectedBootResult = bootResult

		tpmInstance, err := tpm.GetFrom(result.ExpectedBootResult.CurrentState)
		if err != nil {
			return nil, ErrGetPCR0Measurements{Err: fmt.Errorf("unable to obtain the simulated TPM state: %w", err)}
		}
		result.ExpectedTPMState = tpmInstance
	}

	// Real PCR0 values

	if optionsConfig.UsePCR0ExpectedAsCurrent {
		for hashAlgo, pcr0Value := range result.ExpectedTPMState.PCRValues[0] {
			result.PCR0Current[tpm2.Algorithm(hashAlgo)] = pcr0Value
		}
	} else if !optionsConfig.HostNotBooted {
		// TODO: add support of TPM1.2
		// TODO: drop abrmd support after it will be dropped in production.

		// Try abrmd first, if failure then try tpmrm.
		var tpmIO io.ReadWriteCloser
		tpmIO, err = abrmd.NewBroker()
		if tpmIO == nil || err != nil {
			var tpm *hwapi.TPM
			tpm, err = hwapi.NewTPM()
			if tpm != nil {
				tpmIO = tpm.RWC
			}
		}
		if err != nil {
			return nil, ErrTPM{Err: fmt.Errorf("unable to open TPM: %w", err)}
		}
		defer func() {
			_ = tpmIO.Close()
		}()

		for _, alg := range algos {
			result.PCR0Current[alg], err = tpm2.ReadPCR(tpmIO, 0, alg)
			if err != nil {
				return nil, ErrTPM{Err: fmt.Errorf("unable to read PCR0 from TPM: %w", err)}
			}
		}
	}

	// Aligning firmwares

	if result.FirmwareCurrent.UEFI != nil {
		var err error

		result.FirmwareExpected.UEFI, result.FirmwareAlignToCurrentOffset, err = helpers.GetAlignedImage(ctx, result.FirmwareExpected.UEFI, result.FirmwareCurrent.UEFI.Buf())
		if err != nil {
			return nil, ErrAlignFirmwares{Err: fmt.Errorf("unable to align the expected firmware to the current one: %w", err)}
		}

		result.FirmwareOriginal.UEFI, _, err = helpers.GetAlignedImage(ctx, result.FirmwareOriginal.UEFI, result.FirmwareCurrent.UEFI.Buf())
		if err != nil {
			return nil, ErrAlignFirmwares{Err: fmt.Errorf("unable to align the original firmware to the current one: %w", err)}
		}
	}

	return result, nil
}

func getEventLog(filepath string, log logger.Logger) (*tpmeventlog.TPMEventLog, error) {
	// We lose eventlog when do kexec in YARD, and this is not a fault
	// of a vendor or NPIs, so no sense to return a validation error here.
	// Just printing a warning and continuing.
	//
	// See also: https://www.internalfb.com/tasks?t=98458790

	// Symptoms that eventlog doesn't exist: no file or empty file
	if _, err := os.Stat(filepath); errors.Is(err, os.ErrNotExist) {
		if log != nil {
			log.Warnf("no EventLog found in '%s'", filepath)
		}
		return nil, nil
	}

	eventLog, err := os.ReadFile(EventLogPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read eventlog conents: %w", err)
	}

	if len(eventLog) == 0 {
		if log != nil {
			log.Warnf("EventLog file is empty")
		}
		return nil, nil
	}

	return tpmeventlog.Parse(bytes.NewReader(eventLog))
}

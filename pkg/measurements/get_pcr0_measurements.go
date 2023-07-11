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
package measurements

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/amdpsp"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/intelpch"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcrbruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/amdregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/go-tpm/tpm2"
	"github.com/linuxboot/fiano/pkg/intel/metadata/bg"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/immune-gmbh/attestation-sdk/pkg/pcrbruteforcererrors"
	"github.com/immune-gmbh/attestation-sdk/pkg/xtpmeventlog"
)

func init() {
	// It appears Y3DLD11 has wrong order of elements inside BPM:
	// PFRE goes PCDE, thus disabling the host strict order check.
	//
	// TODO: make offsets stable to elements reordering, currently
	// if position of PMSE will be wrong it will show a wrong area
	// in the report.
	bg.StrictOrderCheck = false
	cbnt.StrictOrderCheck = false
}

// SimulateBootProcess returns the result of boot flow simulation.
//
// TODO: Delete this function. It is just a function for an intermediate
//
//	of the code while migrating it from `pcr` to `bootflow`.
func SimulateBootProcess(
	ctx context.Context,
	biosImg *biosimage.BIOSImage,
	registers registers.Registers,
	flow bootflowtypes.Flow,
) *bootengine.BootProcess {
	state := bootflowtypes.NewState()
	state.IncludeSubSystem(tpm.NewTPM())
	state.IncludeSubSystem(intelpch.NewPCH())
	state.IncludeSubSystem(amdpsp.NewPSP())
	state.IncludeSystemArtifact(biosImg)
	state.IncludeSystemArtifact(txtpublic.New(registers))
	state.IncludeSystemArtifact(amdregisters.New(registers))
	state.SetFlow(flow)
	process := bootengine.NewBootProcess(state)
	process.Finish(ctx)
	return process
}

// CalculatePCR0 calculates PCR0 value
//
// TODO: Delete this function. It is just a function for an intermediate
//
//	of the code while migrating it from `pcr` to `bootflow`.
func CalculatePCR0(
	ctx context.Context,
	fw *uefi.UEFI,
	flow bootflowtypes.Flow,
	statusRegisters registers.Registers,
	hashAlgo tpm2.Algorithm,
) ([]byte, error) {
	process := SimulateBootProcess(
		ctx, biosimage.NewFromParsed(fw), statusRegisters, flow,
	)
	if err := process.Log.Error(); err != nil {
		return nil, fmt.Errorf("unable to simulate the boot process: %w", err)
	}
	tpmInstance, err := tpm.GetFrom(process.CurrentState)
	if err != nil {
		return nil, fmt.Errorf("unable to access the simulated TPM: %w", err)
	}
	pcr0Value, err := tpmInstance.PCRValues.Get(0, tpm.Algorithm(hashAlgo))
	if err != nil {
		return nil, fmt.Errorf("unable to obtain the calculated PCR0 value: %w", err)
	}
	return pcr0Value, nil
}

// Issue is a non-critical problem
type Issue error

// GetFixedHostConfiguration returns fixed host configuration elements
//
// TODO: Delete this function. It is just a function for an intermediate
//
//	of the code while migrating it from `pcr` to `bootflow`.
func GetFixedHostConfiguration(
	ctx context.Context,
	originalFW *uefi.UEFI,
	actualImageOffset uint64,
	actualImage []byte,
	regs registers.Registers,
	eventLog *tpmeventlog.TPMEventLog,
	hostPCR0 []byte,
) (retRegs registers.Registers, retIssues []Issue, retErr error) {
	log := logger.FromCtx(ctx)
	defer func() {
		log.Debugf("GetFixedHostConfiguration result: <%v> <%v> <%v>", retRegs, retIssues, retErr)
	}()

	var issues []Issue
	fixedRegisters := regs

	var acmPolicyStatusRobust bool
	if eventLog != nil {
		for _, hashAlg := range []tpmeventlog.TPMAlgorithm{tpmeventlog.TPMAlgorithmSHA1, tpmeventlog.TPMAlgorithmSHA256} {
			pcr0DataLog, _, _ := xtpmeventlog.ExtractPCR0DATALog(eventLog, hashAlg)
			if pcr0DataLog == nil {
				continue
			}
			acmPolicyStatusRobust = true
			acmPolicyStatus := registers.ParseACMPolicyStatusRegister(pcr0DataLog.ACM_POLICY_STATUS)
			log.Infof("Found ACM policy status register: %d in TPM EventLog", acmPolicyStatus)

			var previousValue registers.Register
			previousValue, fixedRegisters = replaceRegister(fixedRegisters, acmPolicyStatus)
			if previousValue != nil {
				log.Infof("Replace initial %08p ACM policy status register with one from TPM eventlog: %08p", previousValue, acmPolicyStatus)
			}
			break
		}
	}

	state := bootflowtypes.NewState()
	state.IncludeSystemArtifact(biosimage.NewFromParsed(originalFW))
	if !acmPolicyStatusRobust && (intelconds.BPMPresent{}).Check(ctx, state) {
		// Currently there is a bug that ACM_POLICY_STATUS register value is corrupted
		// We need bruteforce the real value of ACM_POLICY_STATUS
		// https://premiersupport.intel.com/IPS/5003b00001aHC7N
		updatedACMPolicyStatus, _issues, err := CalculateCBnT0TACMPolicyStatus(
			ctx,
			originalFW,
			actualImageOffset,
			actualImage,
			regs,
			eventLog,
			hostPCR0,
		)
		issues = append(issues, _issues...)
		if err != nil {
			// without proper ACM_POLICY_STATUS register, we should skip further actions
			return nil, issues, fmt.Errorf("failed to reconstruct ACM policy status register: %w", err)
		}
		if updatedACMPolicyStatus == nil {
			log.Infof("ACM policy status register haven't changed")
			return fixedRegisters, issues, nil
		}
		log.Infof("new ACM policy status register value: %08p", *updatedACMPolicyStatus)
		_, fixedRegisters = replaceRegister(fixedRegisters, *updatedACMPolicyStatus)
	}
	return fixedRegisters, issues, nil
}

// CalculateCBnT0TACMPolicyStatus tries to obtain ACM_POLICY_STATUS register from the host configuration using bruteforcing tehniques
//
// TODO: Delete this function. It is just a function for an intermediate
//
//	of the code while migrating it from `pcr` to `bootflow`.
func CalculateCBnT0TACMPolicyStatus(
	ctx context.Context,
	originalFW *uefi.UEFI,
	_ uint64,
	actualImage []byte,
	regs registers.Registers,
	eventLog *tpmeventlog.TPMEventLog,
	hostPCR0 []byte,
) (retACMPS *registers.ACMPolicyStatus, retIssues []Issue, retErr error) {
	log := logger.FromCtx(ctx)
	defer func() {
		log.Debugf("CalculateCBnT0TACMPolicyStatus result: <%v> <%v> <%v>", retACMPS, retIssues, retErr)
	}()

	actualProcess := SimulateBootProcess(ctx, biosimage.New(actualImage), regs, flows.Root) // This is slow, here we parse the actual image
	if err := actualProcess.Log.Error(); err != nil {
		return nil, nil, fmt.Errorf("unable to simulate the boot process: %w", err)
	}
	tpmInstance, err := tpm.GetFrom(actualProcess.CurrentState)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to access the simulated TPM: %w", err)
	}

	var issues []Issue

	if eventLog == nil {
		issues = append(issues, fmt.Errorf("no EventLog provided"))
	} else {
		for _, tpmAlg := range []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256} {
			result, updatedACMPolicyStatus, rIssues, err := pcrbruteforcer.ReproduceEventLog(
				ctx,
				actualProcess,
				eventLog,
				tpmAlg,
				pcrbruteforcer.DefaultSettingsReproduceEventLog(),
			)
			log.Debugf("ReproduceEventLog result: '%v', '%v', '%v'", result, updatedACMPolicyStatus, err)
			if err != nil {
				issues = append(issues, fmt.Errorf("unable to reproduce EventLog: %w", err))
			}
			if len(rIssues) != 0 {
				issues = append(issues, pcrbruteforcererrors.ErrReproduceEventLogIssues{Issues: rIssues})
			}
			if updatedACMPolicyStatus != nil {
				return updatedACMPolicyStatus, issues, nil
			}
			if result != nil {
				// reproduced
				return nil, issues, nil
			}
			log.Infof("Unable to calculate ACM_POLICY_STATUS using eventlog for hash algo '%v': %v", tpmAlg, err)
		}
	}

	if len(hostPCR0) == 0 {
		issues = append(issues, fmt.Errorf("no expected PCR0 provided"))
	} else {
		var hashAlgo tpm2.Algorithm
		switch len(hostPCR0) {
		case sha1.Size:
			hashAlgo = tpm2.AlgSHA1
		case sha256.Size:
			hashAlgo = tpm2.AlgSHA256
		default:
			return nil, issues, fmt.Errorf("unsupported hash algorithm of host PCR0: 0x%X", hostPCR0)
		}

		pcr0Value, err := tpmInstance.PCRValues.Get(0, tpm.Algorithm(hashAlgo))
		if err != nil {
			issues = append(issues, fmt.Errorf("unable to obtain the calculated PCR0 value: %w", err))
		} else {
			if bytes.Equal(pcr0Value, hostPCR0) {
				if current, found := registers.FindACMPolicyStatus(regs); found {
					log.Debugf("Current ACMPolicyStatus register is correct")
					return &current, issues, nil
				}
			}
		}

		reproduceResult, err := pcrbruteforcer.ReproduceExpectedPCR0(
			ctx,
			tpmInstance.CommandLog,
			hashAlgo,
			hostPCR0,
			pcrbruteforcer.DefaultSettingsReproducePCR0(),
		)
		log.Debugf("ReproduceExpectedPCR0 result is: '%v', '%v', '%v'", reproduceResult, err)
		if reproduceResult != nil {
			return reproduceResult.ACMPolicyStatus, issues, err
		}
		issues = append(issues, fmt.Errorf("unable to calculate ACM_POLICY_STATUS using PCR0 based bruteforcer: %w", err))
	}
	return nil, issues, fmt.Errorf("failed to calculate ACM_POLICY_STATUS register")
}

func replaceRegister(regs registers.Registers, newRegister registers.Register) (registers.Register, registers.Registers) {
	var result registers.Registers
	var previousValue registers.Register

	for _, reg := range regs {
		if reg.ID() == newRegister.ID() {
			previousValue = reg
		} else {
			result = append(result, reg)
		}
	}
	result = append(result, newRegister)
	return previousValue, result
}

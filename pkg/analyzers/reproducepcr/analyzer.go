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

package reproducepcr

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcrbruteforcer"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/go-tpm/tpm2"

	"github.com/immune-gmbh/attestation-sdk/if/typeconv"
	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/reproducepcr/report/generated/reproducepcranalysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/flowscompat"
	"github.com/immune-gmbh/attestation-sdk/pkg/measurements"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"

	// TODO: delete this:
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
)

func init() {
	analysis.RegisterType(ExpectedPCR0(nil))
	analysis.RegisterType((*reproducepcranalysis.CustomReport)(nil))
}

// ExpectedPCR0 represents expected PCR0 value from the host
type ExpectedPCR0 []byte

// ID represents the unique id of DiffMeasuredBoot analyzer
const ID analysis.AnalyzerID = reproducepcranalysis.ReproducePCRAnalyzerID

// NewExecutorInput builds an analysis.Executor's input required for ReproducePCR analyzer
//
// Optional arguments: tpm, eventlog and enforcedMeasurementsFlow
func NewExecutorInput(
	originalFirmware analysis.Blob,
	actualFirmware analysis.Blob,
	regs registers.Registers,
	tpm tpmdetection.Type,
	eventlog *tpmeventlog.TPMEventLog,
	enforcedMeasurementsFlow pcr.Flow,
	expectedPCR0 []byte,
) (analysis.Input, error) {
	if actualFirmware == nil {
		return nil, fmt.Errorf("the actual firmware image should be specified")
	}
	if len(expectedPCR0) == 0 {
		return nil, fmt.Errorf("expected PCR0 value should be specified")
	}

	actualRegisters, err := analysis.NewActualRegisters(regs)
	if err != nil {
		return nil, fmt.Errorf("failed to convert registers: %w", err)
	}

	result := analysis.NewInput()
	result.AddOriginalFirmware(
		originalFirmware,
	).AddActualFirmware(
		actualFirmware,
	).AddActualRegisters(
		actualRegisters,
	).AddTPMDevice(
		tpm,
	).AddCustomValue(
		ExpectedPCR0(expectedPCR0),
	)

	if eventlog != nil {
		result.AddTPMEventLog(eventlog)
	}
	if enforcedMeasurementsFlow != pcr.FlowAuto {
		result.ForceBootFlow(flowscompat.FromOld(enforcedMeasurementsFlow))
	}
	return result, nil
}

// Input describes the input data for the ReproducePCR analyzer
type Input struct {
	ReferenceFirmware  analysis.ReferenceFirmware
	ActualFirmwareBlob analysis.ActualFirmwareBlob
	ActualRegisters    analysis.ActualRegisters
	FixedRegisters     analysis.FixedRegisters
	BootFlow           types.BootFlow
	TPMEventLog        *tpmeventlog.TPMEventLog `exec:"optional"`
	ExpectedPCR0       ExpectedPCR0
}

// ReproducePCR is analyzer that tries to reproduce given PCR0 value
type ReproducePCR struct{}

// New returns a new object of ReproducePCR analyzer
func New() analysis.Analyzer[Input] {
	return &ReproducePCR{}
}

// ID implements the ID method required for analysis.Analyzer
func (analyzer *ReproducePCR) ID() analysis.AnalyzerID {
	return ID
}

// Analyze tries to reproduce ExpectedPCR0
//
// TODO: redesign this function, this is an intermediate code while migrating from `pcr` to `bootflow`.
func (analyzer *ReproducePCR) Analyze(ctx context.Context, in Input) (*analysis.Report, error) {
	span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("ReproducePCR_%d", len(in.ExpectedPCR0)))
	defer span.Finish()
	log := logger.FromCtx(ctx)
	log.Debugf("requested flow: %v", in.BootFlow)

	customReport := reproducepcranalysis.CustomReport{}
	report := &analysis.Report{}
	// historically we use values instead of pointers in report.Custom, so we have
	// to assign the value in the end :(
	defer func() {
		report.Custom = customReport
	}()

	acmStatusFixed, foundACMStatusFixed := registers.FindACMPolicyStatus(in.FixedRegisters.GetRegisters())
	if foundACMStatusFixed {
		v, err := registers.ValueBytes(acmStatusFixed)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ACM_POLICY_STATUS register's value: %w", err)
		}
		customReport.ExpectedACMPolicyStatus = v

		acmStatusActual, found := registers.FindACMPolicyStatus(in.ActualRegisters.GetRegisters())
		if !found {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity:    analysis.SeverityInfo,
				Description: fmt.Sprintf("Correct ACM_POLICY_STATUS register value: '0x%X'", acmStatusFixed),
			})
		} else if acmStatusActual.Raw() != acmStatusFixed.Raw() {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity: analysis.SeverityInfo,
				Description: fmt.Sprintf("Correct ACM_POLICY_STATUS register value: '0x%X', initial: '0x%X'",
					acmStatusFixed, acmStatusActual),
			})
		}
	}

	biosImg := biosimage.NewFromParsed(in.ReferenceFirmware.UEFI())
	bootResult, tpmInstance, tpmLocality, matched, err := analyzer.doesPCR0MatchFlow(ctx, biosImg, in.FixedRegisters.GetRegisters(), in.BootFlow, in.ExpectedPCR0)
	if err != nil {
		return nil, fmt.Errorf("unable to check if PCR0 matches in the expected flow: %w", err)
	}

	// TODO: delete this, the hash algorithm should be explicit, and not implicitly inferred from the hash length:
	hashAlgo := hashAlgoForHashLength(ctx, tpmInstance, len(in.ExpectedPCR0))

	// TODO: delete this, this is an intermediate code while migrating from `pcr` to `bootflow`:
	specificFlow := in.BootFlow
	if flowscompat.ToOld(bootflowtypes.Flow(specificFlow)) == pcr.FlowAuto {
		specificFlow = types.BootFlow(measurements.ExtractResultingBootFlow(bootResult.Log))
	}
	logger.FromCtx(ctx).Debugf("specific flow: '%s'", specificFlow.Name)

	// TODO: delete this, this is an intermediate code while migrating from `pcr` to `bootflow`:
	resultFlow, err := typeconv.ToThriftFlow(bootflowtypes.Flow(specificFlow))
	if err != nil {
		return nil, fmt.Errorf("unable to convert flow '%s' to Thrift (case #0): %w", specificFlow.Name, err)
	}
	customReport.ExpectedFlow = resultFlow

	customReport.ExpectedLocality = int8(tpmLocality)

	if matched {
		log.Infof("matched the expected PCR0 (flow: %v)", in.BootFlow)
		return report, nil
	}

	if flow, tpmLocality, matched := analyzer.reproduceUsingKnownFlows(
		ctx,
		biosImg, in.FixedRegisters.GetRegisters(),
		in.ExpectedPCR0,
	); matched {
		log.Infof("matched an unexpected PCR0 flow '%v'", flow)
		resultFlow, err := typeconv.ToThriftFlow(bootflowtypes.Flow(flow))
		if err != nil {
			return nil, fmt.Errorf("unable to convert flow '%s' to Thrift (case #1): %w", flow, err)
		}
		customReport.ExpectedFlow = resultFlow
		customReport.ExpectedLocality = int8(tpmLocality)
		report.Issues = append(report.Issues, analysis.Issue{
			Severity:    analysis.SeverityInfo,
			Description: fmt.Sprintf("Matched with flow: '%s'", flow.Name),
		})
		return report, nil
	}

	settings := pcrbruteforcer.DefaultSettingsReproducePCR0()
	if len(tpmInstance.CommandLog) <= 10 {
		settings.MaxDisabledMeasurements = len(tpmInstance.CommandLog)
	} else {
		settings.MaxDisabledMeasurements = 3
	}

	// TODO: Do not bruteforce ACM Policy Status inside ReproduceExpectedPCR0, since it was already
	//       bruteforced in getFixedRegisters
	// TODO: Do not run ReproduceExpectedPCR0 again, if it was already ran in getFixedRegisters
	//       (it is called for diffmeasuredboot anyway, so we cannot get rid of it).
	reproResult, reproErr := pcrbruteforcer.ReproduceExpectedPCR0(
		ctx,
		tpmInstance.CommandLog,
		hashAlgo,
		bootflowtypes.ConvertedBytes(in.ExpectedPCR0),
		settings,
	)
	log.Infof("reproduceExpectedPCR0 result is: %v %v", reproResult, reproErr)
	if reproErr != nil {
		log.Warnf("Failed to reproduce expected PCR0: %v", reproErr)
		report.Issues = append(report.Issues, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: fmt.Sprintf("Failed to reproduce PCR0 value: %v", reproErr),
		})
	}

	if reproResult == nil {
		log.Warnf("unable to reproduce expected PCR0")
		report.Issues = append(report.Issues, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: "Unable to reproduce PCR0 value",
		})
	} else {
		for _, disabledMeasurement := range reproResult.DisabledMeasurements {
			customReport.DisabledMeasurements = append(customReport.DisabledMeasurements, disabledMeasurement.String())
		}

		if customReport.ExpectedLocality != int8(reproResult.Locality) {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity: analysis.SeverityCritical,
				Description: fmt.Sprintf("Matched for locality: %d, instead of expected: %d",
					reproResult.Locality, customReport.ExpectedLocality),
			})
			customReport.ExpectedLocality = int8(reproResult.Locality)
		}

		if len(customReport.DisabledMeasurements) > 0 {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity: analysis.SeverityCritical,
				Description: fmt.Sprintf("Disabled measurements: '%s'",
					strings.Join(customReport.DisabledMeasurements, ", ")),
			})
		}

		if reproResult.ACMPolicyStatus != nil {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity: analysis.SeverityInfo,
				Description: fmt.Sprintf("Internal problem: ACM policy status was re-corrected from %X (found: %v) to %X",
					acmStatusFixed, foundACMStatusFixed, *reproResult.ACMPolicyStatus),
			})
		}
	}

	if in.TPMEventLog == nil {
		report.Issues = append(report.Issues, analysis.Issue{
			Severity:    analysis.SeverityWarning,
			Description: "TPM EventLog is not provided",
		})
	} else {
		// TODO: Do not run ReproduceEventLog again, if it was already ran in getFixedRegisters
		//       (it is called for diffmeasuredboot anyway, so we cannot get rid of it).
		_, correctedACMPolicyStatus, issues, err := pcrbruteforcer.ReproduceEventLog(
			ctx,
			bootResult,
			in.TPMEventLog,
			hashAlgo,
			pcrbruteforcer.DefaultSettingsReproduceEventLog(),
		)
		if correctedACMPolicyStatus != nil {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity:    analysis.SeverityWarning,
				Description: fmt.Sprintf("According to TPM EventLog ACM Policy Status is %v", *correctedACMPolicyStatus),
			})
		}
		if err != nil {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity:    analysis.SeverityWarning,
				Description: fmt.Sprintf("An error occurred while reproducing TPM EventLog: %v", err),
			})
		}
		for _, issue := range issues {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity:    analysis.SeverityWarning,
				Description: fmt.Sprintf("An issue occurred while reproducing TPM EventLog: %v", issue),
			})
		}
		var log bytes.Buffer
		replayedPCR0, err := tpmeventlog.Replay(in.TPMEventLog, 0, hashAlgo, &log)
		logger.FromCtx(ctx).Debugf("TPM EventLog replay log: %s", log.Bytes())
		if err == nil {
			if bytes.Equal(replayedPCR0, in.ExpectedPCR0) {
				report.Issues = append(report.Issues, analysis.Issue{
					Severity:    analysis.SeverityInfo,
					Description: "Replayed PCR0 (using TPM EventLog) matches the provided PCR0",
				})
			} else {
				report.Issues = append(report.Issues, analysis.Issue{
					Severity:    analysis.SeverityWarning,
					Description: "Replayed PCR0 (using TPM EventLog) does not match the provided PCR0",
				})
			}
		} else {
			report.Issues = append(report.Issues, analysis.Issue{
				Severity:    analysis.SeverityWarning,
				Description: fmt.Sprintf("Unable to replay PCR0 using TPM EventLog: %v", err.Error()),
			})
		}
	}

	return report, nil
}

// TODO: redesign this, this is an intermediate code while migrating from `pcr` to `bootflow`:
func (analyzer *ReproducePCR) reproduceUsingKnownFlows(
	ctx context.Context,
	biosImg *biosimage.BIOSImage,
	actualRegisters registers.Registers,
	expectedPCR0 []byte,
) (types.BootFlow, uint8, bool) {
	allFlows := flows.All()

	{
		// Flows like TXTEnabled and CBnT includes TXTDisabled flow within,
		// because of that TXT-disabled machine actually match the CBnT behavior.
		// But we still would prefer to report it as TXT-disabled, rather than
		// CBnT, so we try flows in a specific order:
		order := map[string]int{
			flows.IntelLegacyTXTDisabled.Name: -1,
		}
		sort.Slice(allFlows, func(i, j int) bool {
			return order[allFlows[i].Name] < order[allFlows[j].Name]
		})
	}

	for _, tryFlow := range allFlows {
		if flowscompat.ToOld(tryFlow) == pcr.FlowAuto {
			// Try only those flows, which maps into something in the old design.
			//
			// This is a temporary solution.
			continue
		}
		_, _, locality, ok, err := analyzer.doesPCR0MatchFlow(ctx, biosImg, actualRegisters, types.BootFlow(tryFlow), expectedPCR0)
		if err != nil {
			// TODO: filter out flows which could not be applied at all and replace Debugf with Errorf:
			logger.FromCtx(ctx).Debugf("unable to try flow %s: %v", tryFlow.Name, err)
			continue
		}
		if ok {
			return types.BootFlow(tryFlow), locality, true
		}
	}
	return types.BootFlow(flows.Root), 0, false
}

func (analyzer *ReproducePCR) doesPCR0MatchFlow(
	ctx context.Context,
	biosImg *biosimage.BIOSImage,
	actualRegisters registers.Registers,
	bootFlow types.BootFlow,
	expectedPCR0 []byte,
) (*bootengine.BootProcess, *tpm.TPM, uint8, bool, error) {
	bootResult := measurements.SimulateBootProcess(
		ctx,
		biosImg,
		actualRegisters,
		bootflowtypes.Flow(bootFlow),
	)
	if err := bootResult.Log.Error(); err != nil {
		return nil, nil, 0, false, fmt.Errorf("unable to simulate a boot process: %w", err)
	}

	tpmInstance, err := tpm.GetFrom(bootResult.CurrentState)
	if err != nil {
		return nil, nil, 0, false, fmt.Errorf("unable to obtain the simulated TPM: %w", err)
	}

	if len(tpmInstance.CommandLog) < 1 {
		return nil, nil, 0, false, fmt.Errorf("the simulated TPM is not initialized")
	}

	tpmInitCmd, ok := tpmInstance.CommandLog[0].Command.(*tpm.CommandInit)
	if !ok {
		return nil, nil, 0, false, fmt.Errorf("the first command to the simulated TPM was not INIT: %T", tpmInstance.CommandLog[0].Command)
	}

	tpmLocality := tpmInitCmd.Locality
	hashAlgo := hashAlgoForHashLength(ctx, tpmInstance, len(expectedPCR0))
	if hashAlgo == tpm2.AlgUnknown {
		return nil, nil, 0, false, fmt.Errorf("unexpected length of the hash: %d", len(expectedPCR0))
	}

	calculatedPCR0, err := tpmInstance.PCRValues.Get(0, hashAlgo)
	if err != nil {
		return nil, nil, 0, false, fmt.Errorf("unable to get the calculated PCR0 for hash algo %s: %w", hashAlgo, err)
	}

	matched := bytes.Equal(calculatedPCR0, expectedPCR0)
	return bootResult, tpmInstance, tpmLocality, matched, nil
}

func hashAlgoForHashLength(ctx context.Context, tpmInstance *tpm.TPM, hashLength int) tpm.Algorithm {
	for _, hashAlgo := range tpmInstance.SupportedAlgos {
		h, err := hashAlgo.Hash()
		if err != nil {
			logger.FromCtx(ctx).Errorf("unable to initialize a hash function for algo %s: %v", hashAlgo, err)
			continue
		}
		if h.Size() == hashLength {
			return hashAlgo
		}
	}

	return tpm2.AlgUnknown
}

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

package diff_measured_boot_areas

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/logger"

	ifanalyzer "github.com/immune-gmbh/attestation-sdk/doc/v2/if/generated/analyzer"
	"github.com/immune-gmbh/attestation-sdk/doc/v2/pkg/analyzer"
	"github.com/immune-gmbh/attestation-sdk/doc/v2/pkg/analyzer/analyzers"
	"github.com/immune-gmbh/attestation-sdk/doc/v2/pkg/analyzer/analyzers/diff_measured_boot_areas/helpers"
	"github.com/immune-gmbh/attestation-sdk/doc/v2/pkg/analyzer/dataconverters"
	"github.com/immune-gmbh/attestation-sdk/pkg/diffdiag"
)

type Input struct {
	DumpedFirmwareReference  analyzers.FirmwareReference
	OriginalFirmwareSelector analyzers.OriginalFirmwareSelector
}

type Output struct {
	DiffEntries   []diff.AnalysisReportEntry
	DiffDiagnosis ifanalyzer.DiffDiagnosis
}

type Analyzer struct {
	DumpedFirmwareStorage   analyzers.DumpedFirmwareStorage
	OriginalFirmwareFetcher analyzers.OriginalFirmwareFetcher
}

func Register(
	registry *analyzer.Registry,
	dumpedFirmwareStorage analyzers.DumpedFirmwareStorage,
	originalFirmwareFetcher analyzers.OriginalFirmwareFetcher,
) {
	registry.RegisterFirmwareAnalyzer(newAnalyzer(dumpedFirmwareStorage, originalFirmwareFetcher), &Output{}, &Input{})
}

func newAnalyzer(
	dumpedFirmwareStorage analyzers.DumpedFirmwareStorage,
	originalFirmwareFetcher analyzers.OriginalFirmwareFetcher,
) *Analyzer {
	return &Analyzer{
		DumpedFirmwareStorage:   dumpedFirmwareStorage,
		OriginalFirmwareFetcher: originalFirmwareFetcher,
	}
}

func (analyzer Analyzer) Analyze(
	ctx context.Context,
	measurements pcr.Measurements,
	dumpedFirmware []byte,
	originalFirmware *uefi.UEFI,
) (*analyzer.Report, analyzer.Error) {
	alignedOriginalImage, imagesOffset, err := helpers.GetAlignedImage(ctx, originalFirmware, dumpedFirmware)
	if err != nil {
		return nil, ErrAlignImages{Err: err}
	}
	ctx = beltctx.WithField(ctx, "imagesOffset", imagesOffset)
	logger.FromCtx(ctx).Debug()

	diffEntries := diff.Diff(measurements.Ranges(), alignedOriginalImage.Buf(), dumpedFirmware, nil)
	diffEntries.SortAndMerge()

	report := diff.Analyze(diffEntries, measurements, alignedOriginalImage, dumpedFirmware)
	diagnosis, diagErr := diffdiag.Diagnose(report.Entries.DiffRanges(), alignedOriginalImage, dumpedFirmware)
	result := &analyzer.Report{
		CustomReport: &Output{
			DiffEntries:   report.Entries,
			DiffDiagnosis: diagnosis,
		},
	}
	if diagErr != nil {
		result.Errors = append(result.Errors, ErrDiag{Err: diagErr})
	}

	switch diagnosis {
	case ifanalyzer.DiffDiagnosis_Match:
	case ifanalyzer.DiffDiagnosis_UnsuspiciousDamage:
		result.Errors = append(result.Errors, ErrUnsuspiciousDamage{})
	case ifanalyzer.DiffDiagnosis_SuspiciousDamage:
		result.Errors = append(result.Errors, ErrSuspiciousDamage{})
	case ifanalyzer.DiffDiagnosis_KnownTamperedHost:
		result.Comments = append(result.Comments, "the firmware was tampered by fwcompromised")
	default:
		result.Errors = append(result.Errors, ErrOtherDiag{Diagnosis: diagnosis})
	}
	return result, nil
}

func (analyzer Analyzer) AbstractAnalyze(
	ctx context.Context,
	_ [][]byte,
	_ analyzer.AnalyzerInput,
	convertedInput []analyzer.DataOutput,
	_ []analyzer.AnalyzerOutput,
) (*analyzer.Report, analyzer.Error) {
	return analyzer.Analyze(
		ctx,
		convertedInput[0].(dataconverters.MeasurementsInfo).Measurements,
		convertedInput[1].([]byte),
		convertedInput[2].(*uefi.UEFI))
}

func (analyzer Analyzer) DataConverters(
	ctx context.Context,
	artifacts [][]byte,
	_input analyzer.AnalyzerInput,
) []analyzer.DataConverter {
	input := _input.(*Input)
	return []analyzer.DataConverter{
		dataconverters.GetOriginalMeasurements(
			analyzer.OriginalFirmwareFetcher,
			input.OriginalFirmwareSelector,
		),
		dataconverters.GetFirmwareBytes(
			analyzer.DumpedFirmwareStorage,
			input.DumpedFirmwareReference,
			artifacts,
		),
		dataconverters.ParseOriginalFirmware(
			analyzer.OriginalFirmwareFetcher,
			input.OriginalFirmwareSelector,
		),
	}
}

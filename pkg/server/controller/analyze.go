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
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/if/typeconv"
	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/amd/apcbsectokens"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/amd/biosrtmvolume"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/amd/pspsignature"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/diffmeasuredboot"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/intelacm"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/reproducepcr"
	"github.com/immune-gmbh/attestation-sdk/pkg/server/controller/analyzerinput"
	controllererrors "github.com/immune-gmbh/attestation-sdk/pkg/server/controller/errors"
	"github.com/immune-gmbh/attestation-sdk/pkg/storage/models"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"
)

// Analyze provides firmware analysis by specified algorithms
func (ctrl *Controller) Analyze(
	ctx context.Context,
	hostInfo *afas.HostInfo,
	artifacts []afas.Artifact,
	analyzers []afas.AnalyzerInput,
) (*afas.AnalyzeResult_, error) {
	jobID := types.NewJobID()
	ctx = beltctx.WithField(ctx, "jobID", jobID)
	log := logger.FromCtx(ctx)

	report, err := ctrl.getAnalyzeReport(ctx, jobID, hostInfo, artifacts, analyzers)
	if err != nil {
		return nil, fmt.Errorf("unable to get the analyze report: %w", err)
	}

	func() {
		defer func() {
			errmon.ObserveRecoverCtx(ctx, recover())
		}()
		span, ctx := tracer.StartChildSpanFromCtx(ctx, "saveAnalyzerReport")
		defer span.Finish()
		if err := ctrl.FirmwareStorage.InsertAnalyzeReport(ctx, report); err != nil {
			log.Errorf("unable to save the report: %v", err)
		} else {
			log.Debugf("successfully saved the AnalyzeReport: %#+v", report)
		}
	}()

	return typeconv.ToThriftAnalyzeReport(report), nil
}

func (ctrl *Controller) getAnalyzeReport(
	ctx context.Context,
	jobID types.JobID,
	_hostInfo *afas.HostInfo,
	artifacts []afas.Artifact,
	analyzerInputs []afas.AnalyzerInput,
) (*models.AnalyzeReport, error) {
	span, ctx := tracer.StartChildSpanFromCtx(ctx, "getAnalyzeReport")
	defer span.Finish()

	hostInfo, _ := ctrl.getHostInfo(ctx, _hostInfo)

	report := &models.AnalyzeReport{
		Timestamp:       time.Now(),
		JobID:           jobID,
		AnalyzerReports: make([]models.AnalyzerReport, len(analyzerInputs)),
	}
	if hostInfo != nil {
		report.AssetID = hostInfo.AssetID
	}
	ctx = beltctx.WithField(ctx, "assetID", hostInfo.GetAssetID())
	log := logger.FromCtx(ctx)
	log.Infof("new Analyze job")

	artifactsAccessor, err := analyzerinput.NewArtifactsAccessor(
		artifacts,
		NewAnalyzerFirmwaresAccessor(ctrl.FirmwareStorage, ctrl.OriginalFWImageRepository, ctrl, hostInfo.ModelID),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create artifacts accessor: %w", err)
	}

	// scopeCache helps to share all calculated results between all analyzers without putting restrictions of consuming identical set of artifacts
	scopeCache := analysis.NewDataCache()
	var (
		wg          sync.WaitGroup
		resultMutex sync.Mutex
	)
	for idx, analyzerThriftInput := range analyzerInputs {
		wg.Add(1)
		go func(idx int, analyzerThriftInput afas.AnalyzerInput) {
			defer wg.Done()

			var (
				analyzerInput  analysis.Input
				inputErr       error
				analyzerID     analysis.AnalyzerID
				analyzerReport *analysis.Report
				analyzerErr    error
			)

			// TODO: Generalize input data conversion, do not require to list each input type in package `controller`.
			//       The set of analyzers should be injected, not hardcoded. The implementation of `controller` should
			//       be agnostic of specific analyzer implementations.
			switch {
			case analyzerThriftInput.IsSetDiffMeasuredBoot():
				span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("AnalyzerWithInput-%s", diffmeasuredboot.ID))
				defer span.Finish()
				analyzerInput, inputErr = analyzerinput.NewDiffMeasuredBootInput(ctx, artifactsAccessor, *analyzerThriftInput.GetDiffMeasuredBoot())
				analyzerID, analyzerReport, analyzerErr = executeAnalyzer[diffmeasuredboot.Input](ctx, ctrl, hostInfo, scopeCache, analyzerInput, diffmeasuredboot.ID)
			case analyzerThriftInput.IsSetReproducePCR():
				span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("AnalyzerWithInput-%s", reproducepcr.ID))
				defer span.Finish()
				analyzerInput, inputErr = analyzerinput.NewReproducePCRInput(ctx, artifactsAccessor, *analyzerThriftInput.GetReproducePCR())
				analyzerID, analyzerReport, analyzerErr = executeAnalyzer[reproducepcr.Input](ctx, ctrl, hostInfo, scopeCache, analyzerInput, reproducepcr.ID)
			case analyzerThriftInput.IsSetIntelACM():
				span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("AnalyzerWithInput-%s", intelacm.ID))
				defer span.Finish()
				analyzerInput, inputErr = analyzerinput.NewIntelACMInput(ctx, artifactsAccessor, *analyzerThriftInput.GetIntelACM())
				analyzerID, analyzerReport, analyzerErr = executeAnalyzer[intelacm.Input](ctx, ctrl, hostInfo, scopeCache, analyzerInput, intelacm.ID)
			case analyzerThriftInput.IsSetPSPSignature():
				span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("AnalyzerWithInput-%s", pspsignature.ID))
				defer span.Finish()
				analyzerInput, inputErr = analyzerinput.NewPSPSignatureInput(ctx, artifactsAccessor, *analyzerThriftInput.GetPSPSignature())
				analyzerID, analyzerReport, analyzerErr = executeAnalyzer[pspsignature.Input](ctx, ctrl, hostInfo, scopeCache, analyzerInput, pspsignature.ID)
			case analyzerThriftInput.IsSetBIOSRTMVolume():
				span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("AnalyzerWithInput-%s", biosrtmvolume.ID))
				defer span.Finish()
				analyzerInput, inputErr = analyzerinput.NewBIOSRTMVolumeInput(ctx, artifactsAccessor, *analyzerThriftInput.GetBIOSRTMVolume())
				analyzerID, analyzerReport, analyzerErr = executeAnalyzer[biosrtmvolume.Input](ctx, ctrl, hostInfo, scopeCache, analyzerInput, biosrtmvolume.ID)
			case analyzerThriftInput.IsSetAPCBSecurityTokens():
				span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("AnalyzerWithInput-%s", apcbsectokens.ID))
				defer span.Finish()
				analyzerInput, inputErr = analyzerinput.NewAPCBSecurityTokensInput(ctx, artifactsAccessor, *analyzerThriftInput.GetAPCBSecurityTokens())
				analyzerID, analyzerReport, analyzerErr = executeAnalyzer[apcbsectokens.Input](ctx, ctrl, hostInfo, scopeCache, analyzerInput, apcbsectokens.ID)
			default:
				log.Errorf("Not supported analyzer: %s", &analyzerThriftInput)
				resultMutex.Lock()
				report.AnalyzerReports[idx] = models.AnalyzerReport{
					ExecError: models.SQLErrorWrapper{Err: controllererrors.ErrUnknownAnalyzer{AnalyzerInput: analyzerThriftInput}},
				}
				resultMutex.Unlock()
				return
			}

			if inputErr != nil {
				log.Errorf("Failed to construct input for analyzer: '%s': '%v'", analyzerID, inputErr)
				analyzerErr = controllererrors.ErrInvalidInput{Err: inputErr}
			}
			resultMutex.Lock()
			// Lock isn't really needed, because we assign values by aligned words and there could
			// not be any problem with concurrency, but just for semantic cleanness keeping them.
			report.AnalyzerReports[idx] = models.AnalyzerReport{
				AnalyzerID: analyzerID,
				Input:      analyzerInput,
				Report:     analyzerReport,
				ExecError:  models.SQLErrorWrapper{Err: analyzerErr},
			}
			resultMutex.Unlock()
		}(idx, analyzerThriftInput)
	}
	wg.Wait()

	return report, nil
}

func executeAnalyzer[analyzerInputType any](
	ctx context.Context,
	ctrl *Controller,
	hostInfo *afas.HostInfo,
	scopeCache analysis.DataCache,
	analyzerInput analysis.Input,
	analyzerID analysis.AnalyzerID,
) (analysis.AnalyzerID, *analysis.Report, error) {
	if analyzerInput == nil {
		return analyzerID, nil, fmt.Errorf("no valid input provided")
	}
	if hostInfo != nil && hostInfo.AssetID != nil {
		// TODO: Our analyzers are not AssetID-agnostic? Fix this. Analyzers
		//       should know nothing about our infra (and should be opensourcable).
		analyzerInput.AddAssetID(*hostInfo.AssetID)
	}

	analyzer := analyzers.Get[analyzerInputType](ctrl.analyzersRegistry, analyzerID)
	if analyzer == nil {
		return analyzerID, nil, fmt.Errorf("analyzer with id '%s' is not found", analyzerID)
	}

	span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("Analyzer-%s", analyzerID))
	defer span.Finish()
	report, err := analysis.ExecuteAnalyzer(ctx, ctrl.analysisDataCalculator, analyzer, analyzerInput, scopeCache)
	return analyzerID, report, err
}

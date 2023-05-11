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
package replay

import (
	"context"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/apcbsectokens"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/biosrtmvolume"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/pspsignature"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/reproducepcr"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/blobstorage"
	controllertypes "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"

	"github.com/facebookincubator/go-belt/tool/logger"
)

// AnalyzerReport executes an analyzer using inputs of an analyzer report with given ID.
// Returns a regenerated report.
func AnalyzerReport(
	ctx context.Context,
	blobstoreURL string,
	rdbmsDriver string,
	rdbmsURL string,
	analyzerReportID int64,
) (*models.AnalyzerReport, error) {
	blobStorage, err := blobstorage.New(blobstoreURL)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize the blob storage using URL '%s': %w", blobstoreURL, err)
	}
	defer func() {
		if err := blobStorage.Close(); err != nil {
			logger.FromCtx(ctx).Error(err)
		}
	}()

	stor, err := storage.New(rdbmsDriver, rdbmsURL, blobStorage, nil, logger.FromCtx(ctx).WithField("module", "storage"))
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Storage client: %w", err)
	}
	defer func() {
		if err := stor.Close(); err != nil {
			logger.FromCtx(ctx).Error(err)
		}
	}()

	report, err := stor.FindAnalyzerReport(nil, analyzerReportID)
	if err != nil {
		return nil, fmt.Errorf("unable to find analyzer report (ID: %d): %w", analyzerReportID, err)
	}

	// prepareImage initializes an analysis.Blob:
	//
	// Currently AFAS's `controller` uses `controllertypes.AnalyzerFirmwareAccessor`
	// as an implementation of `analysis.Blob` which does not contain the image itself
	// in public fields (but only the ImageID instead), so after deserialization we
	// are required to download the image and feed it into the accessor.
	prepareImage := func(blobIface analysis.Blob) error {
		blob := blobIface.(*controllertypes.AnalyzerFirmwareAccessor)

		b, err := stor.GetFirmwareBytes(ctx, blob.ImageID)
		if err != nil {
			return fmt.Errorf("unable to get the image (ID %v): %w", blob.ImageID, err)
		}

		// blob is a pointer thus we can initialize the accessor right here:
		blob.Init(b, nil, nil)
		return nil
	}

	for _, v := range report.Input {
		var err error
		switch v := v.(type) {
		case *analysis.ActualFirmwareBlob:
			err = prepareImage(v.Blob)
		case *analysis.OriginalFirmwareBlob:
			err = prepareImage(v.Blob)
		}
		if err != nil {
			return nil, err
		}
	}

	// TODO: infer analyzer from input type, instead of this switch with analyzer ID constants
	switch report.AnalyzerID {
	case apcbsectokens.ID:
		report.Report, report.ExecError.Err = executeAnalyzer[apcbsectokens.Input](ctx, report)
	case biosrtmvolume.ID:
		report.Report, report.ExecError.Err = executeAnalyzer[biosrtmvolume.Input](ctx, report)
	case pspsignature.ID:
		report.Report, report.ExecError.Err = executeAnalyzer[pspsignature.Input](ctx, report)
	case diffmeasuredboot.ID:
		report.Report, report.ExecError.Err = executeAnalyzer[diffmeasuredboot.Input](ctx, report)
	case intelacm.ID:
		report.Report, report.ExecError.Err = executeAnalyzer[intelacm.Input](ctx, report)
	case reproducepcr.ID:
		report.Report, report.ExecError.Err = executeAnalyzer[reproducepcr.Input](ctx, report)
	default:
		return nil, fmt.Errorf("unknown analyzer (ID '%s')", report.AnalyzerID)
	}
	return report, nil
}

func executeAnalyzer[analyzerInputType any](
	ctx context.Context,
	report *models.AnalyzerReport,
) (*analysis.Report, error) {
	analyzersRegistry, err := analyzers.NewRegistryWithKnownAnalyzers()
	if err != nil {
		return nil, fmt.Errorf("unable to get analyzers registry: %w", err)
	}

	analyzer := analyzers.Get[analyzerInputType](analyzersRegistry, report.AnalyzerID)
	if analyzer == nil {
		return nil, fmt.Errorf("analyzer with ID '%s' is not found", report.AnalyzerID)
	}

	dataCalculator, err := analysis.NewDataCalculator(100)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize data calculator: %w", err)
	}

	return analysis.ExecuteAnalyzer(ctx, dataCalculator, analyzer, report.Input, nil)
}

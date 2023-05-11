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

	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/typeconv"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

type SearchReportResult = afas.SearchReportResult_

// SearchReport a previously saved report (it is extracted from scuba).
func (ctrl *Controller) SearchReport(
	ctx context.Context,
	requestFilters []*afas.SearchReportFilters,
	limit uint64,
) (*SearchReportResult, error) {
	if len(requestFilters) != 1 {
		return nil, fmt.Errorf("currently we support only one OR-filter (received: %d) [is not implemented]", len(requestFilters))
	}
	span, ctx := tracer.StartChildSpanFromCtx(ctx, "")
	defer span.Finish()

	findFilter := storage.AnalyzeReportFindFilter{}
	requestFilter := requestFilters[0]
	if requestFilter.JobID != nil {
		var jobID types.JobID
		if len(requestFilter.JobID) != len(jobID) {
			return nil, fmt.Errorf("invalid length of a job ID: received:%d != expected:%d", len(requestFilter.JobID), len(jobID))
		}
		copy(jobID[:], requestFilter.JobID)
		findFilter.JobID = &jobID
	}
	if requestFilter.AssetID != nil {
		assetID := int32(*requestFilter.AssetID)
		findFilter.AssetID = &assetID
	}
	if requestFilter.ActualFirmware != nil {
		if requestFilter.ActualFirmware.ImageID != nil {
			var imageID types.ImageID
			if len(requestFilter.ActualFirmware.ImageID) != len(imageID) {
				return nil, fmt.Errorf("invalid length of a actual image ID: received:%d != expected:%d", len(requestFilter.ActualFirmware.ImageID), len(imageID))
			}
			copy(imageID[:], requestFilter.ActualFirmware.ImageID)
			findFilter.ActualFirmware.ImageID = &imageID
		}
		findFilter.ActualFirmware.HashBlake3_512 = requestFilter.ActualFirmware.HashBlake3_512
		findFilter.ActualFirmware.HashSHA2_512 = requestFilter.ActualFirmware.HashSHA2_512
		findFilter.ActualFirmware.FirmwareVersion = requestFilter.ActualFirmware.Version
		findFilter.ActualFirmware.Filename = requestFilter.ActualFirmware.Filename
		findFilter.ActualFirmware.HashStable = requestFilter.ActualFirmware.HashStable
	}

	reports, err := ctrl.FirmwareStorage.FindAnalyzeReports(ctx, findFilter, nil, uint(limit))
	if err != nil {
		return nil, fmt.Errorf("unable to find the report: %w", err)
	}
	logger.FromCtx(ctx).Debugf("found reports: %d", len(reports))

	result := &SearchReportResult{}
	for _, report := range reports {
		result.Found = append(result.Found, typeconv.ToThriftAnalyzeReport(report))
	}

	return result, nil
}

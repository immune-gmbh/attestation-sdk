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

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/pkg/firmwaredb"
)

// CheckFirmwareVersion checks
func (ctrl *Controller) CheckFirmwareVersion(
	ctx context.Context,
	checkedVersions []afas.FirmwareVersion,
) ([]bool, error) {
	log := logger.FromCtx(ctx)
	var versionsFilters firmwaredb.FiltersOR

	checked := make([]*firmwareVersionDate, len(checkedVersions))
	for _, firmwareVersion := range checkedVersions {
		versionsFilters = append(versionsFilters, firmwaredb.Filters{
			firmwaredb.FilterVersion(firmwareVersion.Version),
		})
	}

	firmwares, err := ctrl.OriginalFWDB.Get(ctx, versionsFilters)
	if err != nil {
		log.Errorf("Failed to get firmwares: %v", err)
		return nil, err
	}

	selectedVersionsDate := make(map[firmwareVersionDate]struct{})
	for _, fw := range firmwares {
		selectedVersionsDate[firmwareVersionDate{
			version: fw.Version,
		}] = struct{}{}
	}

	result := make([]bool, len(checkedVersions))
	for idx, checkedVersion := range checked {
		var found bool
		if checkedVersion != nil {
			_, found = selectedVersionsDate[*checkedVersion]
		}
		result[idx] = found
	}

	return result, nil
}

type firmwareVersionDate struct {
	version string
}

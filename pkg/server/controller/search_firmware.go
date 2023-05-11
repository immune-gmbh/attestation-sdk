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
	"errors"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

// SearchFirmwareResult is the metadata information about firmwares which fits
// // into requested select/search filters.
type SearchFirmwareResult = afas.SearchFirmwareResult_

// SearchFirmware returns metadata information about firmwares which fits
// into requested select/search filters.
func (ctrl *Controller) SearchFirmware(
	ctx context.Context,
	filters []*afas.SearchFirmwareFilters,
	shouldFetchContent bool,
) (*SearchFirmwareResult, error) {
	result := &SearchFirmwareResult{}
	for _, filter := range filters {
		var (
			imageID       *types.ImageID
			imageIDPrefix []byte
		)
		if filter.ImageID != nil {
			if len(filter.ImageID) > len(types.ImageID{}) {
				return nil, fmt.Errorf("invalid ImageID length: %d > %d", len(filter.ImageID), len(types.ImageID{}))
			}
			if len(filter.ImageID) == len(types.ImageID{}) {
				_imgID := types.NewImageIDFromBytes(filter.ImageID)
				imageID = &_imgID
			} else {
				imageIDPrefix = filter.ImageID
			}
		}
		entries, unlockFn, err := ctrl.FirmwareStorage.FindFirmware(
			ctx,
			storage.FindFirmwareFilter{
				ImageID:         imageID,
				ImageIDPrefix:   imageIDPrefix,
				HashSHA2_512:    filter.HashSHA2_512,
				HashBlake3_512:  filter.HashBlake3_512,
				HashStable:      filter.HashStable,
				Filename:        filter.Filename,
				FirmwareVersion: filter.Version,
			},
		)
		if errors.As(err, &storage.ErrNotFound{}) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("unable to find image metadata: %w", err)
		}
		unlockFn()
		for _, entry := range entries {
			metadata := entry.ToThrift()
			if entry.TSUpload.Valid {
				metadata.TSUpload = &[]int64{entry.TSUpload.Time.UnixNano()}[0]
			}

			var data []byte
			if shouldFetchContent {
				data, err = ctrl.FirmwareStorage.GetFirmwareBytes(ctx, entry.ImageID)
				if err != nil {
					return nil, fmt.Errorf("unable to fetch image data: %w", err)
				}
			}

			result.Found = append(result.Found, &afas.Firmware{
				Metadata: metadata,
				Data:     data,
			})
		}
	}
	return result, nil
}

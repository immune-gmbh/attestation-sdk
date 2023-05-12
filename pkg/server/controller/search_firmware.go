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
		entries, unlockFn, err := ctrl.FirmwareStorage.Find(
			ctx,
			storage.FindFilter{
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
				data, err = ctrl.FirmwareStorage.GetBytes(ctx, entry.ImageID)
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

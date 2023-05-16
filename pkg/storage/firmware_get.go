package storage

import (
	"context"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/lockmap"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

// GetFirmware returns an image and the metadata by ImageID
// (basically combines FindFirmwareOne and GetFirmwareBytes).
func (stor *Storage) GetFirmware(ctx context.Context, imageID types.ImageID) ([]byte, *models.FirmwareImageMetadata, error) {
	meta, unlockFunc, err := stor.FindFirmwareOne(ctx, FindFirmwareFilter{ImageID: &imageID})
	if err != nil {
		return nil, nil, ErrGetMeta{Err: err}
	}
	defer unlockFunc()

	imageBytes, err := stor.GetFirmwareBytes(ctx, imageID)
	if err != nil {
		return nil, nil, ErrGetData{Err: err}
	}

	return imageBytes, meta, nil
}

// GetFirmwareBytes returns an image itself only by ImageID.
func (stor *Storage) GetFirmwareBytes(ctx context.Context, imageID types.ImageID) (firmwareImage []byte, err error) {
	return stor.GetFirmwareBytesByPath(ctx, imageID.BlobStoragePath())
}

// GetFirmwareBytesByPath returns an image itself only by its path in the BlobStorage
func (stor *Storage) GetFirmwareBytesByPath(ctx context.Context, imagePath string) (firmwareImage []byte, err error) {
	type getBytesByPathResult struct {
		firmwareImage []byte
		err           error
	}
	cacheKey, cacheKeyErr := objhash.Build("GetBytesByPath", imagePath)
	var unlocker *lockmap.Unlocker
	if cacheKeyErr == nil {
		unlocker = stor.CacheLockMap.Lock(cacheKey)
		defer unlocker.Unlock()

		if result, ok := unlocker.UserData.(getBytesByPathResult); ok {
			return result.firmwareImage, result.err
		}

		// Since this storage is by design content-addressed, we can safely
		// assume full cache coherence for a specific blob storage path (if the file exist).
		cachedValue, ok := stor.Cache.Get(ctx, cacheKey).([]byte)
		if ok {
			return cachedValue, nil
		}
	}
	err = stor.retryLoop(func() (err error) {
		firmwareImage, err = stor.BlobStorage.Get(ctx, imagePath)
		return
	})
	if unlocker != nil {
		unlocker.UserData = getBytesByPathResult{
			firmwareImage: firmwareImage,
			err:           err,
		}
	}
	if err != nil {
		return nil, ErrDownload{Err: err}
	}
	if cacheKeyErr == nil {
		stor.Cache.Set(ctx, cacheKey, firmwareImage, uint64(len(firmwareImage)))
	}
	return
}

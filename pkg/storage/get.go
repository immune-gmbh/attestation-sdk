package storage

import (
	"context"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/lockmap"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

// Get returns an image and the metadata by ImageID
// (basically combines FindOne and GetBytes).
func (stor *Storage) Get(ctx context.Context, imageID types.ImageID) ([]byte, *models.ImageMetadata, error) {
	meta, unlockFunc, err := stor.FindOne(ctx, FindFirmwareFilter{ImageID: &imageID})
	if err != nil {
		return nil, nil, ErrGetMeta{Err: err}
	}
	defer unlockFunc()

	imageBytes, err := stor.GetBytes(ctx, imageID)
	if err != nil {
		return nil, nil, ErrGetData{Err: err}
	}

	return imageBytes, meta, nil
}

// GetBytes returns an image itself only by ImageID.
func (stor *Storage) GetBytes(ctx context.Context, imageID types.ImageID) (firmwareImage []byte, err error) {
	return stor.getBytesByPath(ctx, imageID.ManifoldPath())
}

// getBytesByPath returns an image itself only by its path in the Manifold bucket.
func (stor *Storage) getBytesByPath(ctx context.Context, imagePath string) (firmwareImage []byte, err error) {
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
		// assume full cache coherence for a specific manifold path (if the file exist).
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

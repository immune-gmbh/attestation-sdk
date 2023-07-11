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
package storage

import (
	"context"

	"github.com/immune-gmbh/attestation-sdk/pkg/lockmap"
	"github.com/immune-gmbh/attestation-sdk/pkg/objhash"
	"github.com/immune-gmbh/attestation-sdk/pkg/storage/models"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"
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
	return stor.GetFirmwareBytesByBlobStoreKey(ctx, imageID.BlobStorageKey())
}

// GetFirmwareBytesByPath returns an image itself only by its path in the BlobStorage
func (stor *Storage) GetFirmwareBytesByBlobStoreKey(ctx context.Context, blobStoreKey []byte) (firmwareImage []byte, err error) {
	type getBytesByPathResult struct {
		firmwareImage []byte
		err           error
	}
	cacheKey, cacheKeyErr := objhash.Build("GetBytesByPath", blobStoreKey)
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
		firmwareImage, err = stor.BlobStorage.Get(ctx, blobStoreKey)
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

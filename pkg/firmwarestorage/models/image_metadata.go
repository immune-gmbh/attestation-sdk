package models

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

// ImageMetadata is a metadata of a stored firmware image.
// noinspection GoSnakeCaseUsage
type ImageMetadata struct {
	ImageID            types.ImageID   `db:"image_id,pk"`
	FirmwareVersion    sql.NullString  `db:"firmware_version"`
	FirmwareDateString sql.NullString  `db:"firmware_date"`
	Filename           sql.NullString  `db:"filename"`
	Size               uint64          `db:"size"`
	TSAdd              time.Time       `db:"ts_add"`
	TSUpload           sql.NullTime    `db:"ts_upload"`
	HashSHA2_512       types.HashValue `db:"hash_sha2_512"`
	HashBlake3_512     types.HashValue `db:"hash_blake3_512"`
	HashStable         types.HashValue `db:"hash_stable"`
}

// NewImageMetadata returns a new instance of image metadata.
func NewImageMetadata(
	image []byte,
	firmwareVersion string,
	firmwareDate string,
	filename string,
) ImageMetadata {
	meta := ImageMetadata{
		TSAdd: time.Now(),
	}
	if firmwareVersion != "" {
		meta.FirmwareVersion = sql.NullString{
			String: firmwareVersion,
			Valid:  true,
		}
	}
	if firmwareDate != "" {
		meta.FirmwareDateString = sql.NullString{
			String: firmwareDate,
			Valid:  true,
		}
	}
	if filename != "" {
		meta.Filename = sql.NullString{
			String: filename,
			Valid:  true,
		}
	}
	meta.CalcMissingInfo(context.Background(), image)
	return meta
}

// CalcMissingInfo calculates values for empty fields based on the image
func (meta *ImageMetadata) CalcMissingInfo(ctx context.Context, image []byte) {
	var wg sync.WaitGroup
	if meta.ImageID.IsZero() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta.ImageID = types.NewImageIDFromImage(image)
		}()
	}
	if meta.Size == 0 {
		meta.Size = uint64(len(image))
	}
	if meta.HashSHA2_512 == nil {
		// TODO: deduplicate calculations with ImageID
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta.HashSHA2_512 = types.Hash(types.HashAlgSHA2_512, image)
		}()
	}
	if meta.HashBlake3_512 == nil {
		// TODO: deduplicate calculations with ImageID
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta.HashBlake3_512 = types.Hash(types.HashAlgBlake3_512, image)
		}()
	}
	if meta.HashStable == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			meta.HashStable, err = types.NewImageStableHashFromImage(image)
			if err != nil {
				logger.FromCtx(ctx).Warnf("unable to calculate the stable hash for image %v: %w", meta.ImageID, err)
			}
		}()
	}
	wg.Wait()
}

// ManifoldPath return the path should be used to store the image in the Manifold.
func (meta ImageMetadata) ManifoldPath() string {
	return meta.ImageID.ManifoldPath()
}

// ToThrift converts ImageMetadata to the structure defined in the Thrift model.
// noinspection GoSnakeCaseUsage
func (meta *ImageMetadata) ToThrift() *afas.FirmwareImageMetadata {
	result := &afas.FirmwareImageMetadata{
		ImageID:        meta.ImageID[:],
		HashSHA2_512:   meta.HashSHA2_512,
		HashBlake3_512: meta.HashBlake3_512,
		HashStable:     meta.HashStable,
		Size:           int64(meta.Size),
		TSAdd:          meta.TSAdd.UnixNano(),
	}

	if meta.Filename.Valid {
		result.Filename = &meta.Filename.String
	}
	if meta.FirmwareVersion.Valid {
		result.Version = &meta.FirmwareVersion.String
	}
	if meta.FirmwareDateString.Valid {
		result.ReleaseDate = &meta.FirmwareDateString.String
	}
	if meta.TSUpload.Valid {
		result.TSUpload = &[]int64{meta.TSUpload.Time.UnixNano()}[0]
	}
	return result
}

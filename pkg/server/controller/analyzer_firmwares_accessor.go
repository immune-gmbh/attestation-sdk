package controller

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/dmidecode"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarestorage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/lockmap"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/analyzerinput"
	controllertypes "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/uefi"
)

// AnalyzerFirmwareAccessor implements analysis.Blob, but it is
// serialized with the ImageID instead of the image content.
type AnalyzerFirmwareAccessor = controllertypes.AnalyzerFirmwareAccessor

// knownFirmware combines firmware image metadata and data together.
type analyzerFirmwaresAccessorResult struct {
	Blob  analysis.Blob
	Error error
}

type imageSaverAsync interface {
	saveImageAsync(
		ctx context.Context,
		meta models.ImageMetadata,
		firmwareImage []byte,
	)
}

// AnalyzerFirmwaresAccessor implements analyzerinput.FirmwaresAccessor for a Controller
type AnalyzerFirmwaresAccessor struct {
	storage                          FirmwareStorage
	rtpFW                            rtpfwInterface
	originalFirmwareStorage          originalFWImageRepository
	imageSaverAsync                  imageSaverAsync
	targetModelFamilyID              *uint64
	firmwareExpectedEvaluationStatus sdf //rtp.EvaluationStatus
	cache                            map[objhash.ObjHash]analyzerFirmwaresAccessorResult
	cacheLocker                      sync.Mutex
	cacheSingleOp                    *lockmap.LockMap
}

var _ analyzerinput.FirmwaresAccessor = (*AnalyzerFirmwaresAccessor)(nil)

// NewAnalyzerFirmwaresAccessor creates a new instance of AnalyzerFirmwaresAccessor.
// It provides firmware images as serializable analysis.Blob-s. Serialized analysis.Blob will
// contain only ImageID to an image, which is saved to the Manifold storage. Thus any
// of these analysis.Blob-s could be saved to MySQL (as part of an Analyze report),
// deserialized back and reused.
//
// TODO: try to polish-up function signature (for example, consider merging rtpFW and firmwareEvaluationStatus)
func NewAnalyzerFirmwaresAccessor(
	storage FirmwareStorage,
	rtpFW rtpfwInterface,
	originalFirmwareStorage originalFWImageRepository,
	imageSaverAsync imageSaverAsync,
	targetModelFamilyID *uint64,
	firmwareExpectedEvaluationStatus sdf, //rtp.EvaluationStatus,
) *AnalyzerFirmwaresAccessor {
	return &AnalyzerFirmwaresAccessor{
		storage:                          storage,
		rtpFW:                            rtpFW,
		originalFirmwareStorage:          originalFirmwareStorage,
		imageSaverAsync:                  imageSaverAsync,
		targetModelFamilyID:              targetModelFamilyID,
		firmwareExpectedEvaluationStatus: firmwareExpectedEvaluationStatus,
		cache:                            make(map[objhash.ObjHash]analyzerFirmwaresAccessorResult),
		cacheSingleOp:                    lockmap.NewLockMap(),
	}
}

func (a *AnalyzerFirmwaresAccessor) saveImageAsync(
	ctx context.Context,
	meta models.ImageMetadata,
	image []byte,
) {
	a.imageSaverAsync.saveImageAsync(ctx, meta, image)
}

func setHashes(ctx context.Context, meta models.ImageMetadata, image []byte) models.ImageMetadata {
	span, ctx := tracer.StartChildSpanFromCtx(ctx, "setHashes")
	defer span.Finish()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		span, _ := tracer.StartChildSpanFromCtx(ctx, "setHashes-ImageID")
		defer span.Finish()
		meta.ImageID = types.NewImageIDFromImage(image)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		span, _ := tracer.StartChildSpanFromCtx(ctx, "setHashes-SHA2-512")
		defer span.Finish()
		meta.HashSHA2_512 = types.Hash(types.HashAlgSHA2_512, image)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		span, _ := tracer.StartChildSpanFromCtx(ctx, "setHashes-Blake3-512")
		defer span.Finish()
		meta.HashBlake3_512 = types.Hash(types.HashAlgBlake3_512, image)
	}()

	wg.Wait()
	return meta
}

func (a *AnalyzerFirmwaresAccessor) metaByImage(
	ctx context.Context,
	image []byte,
	parsedCache *uefi.UEFI,
	filename string,
) (models.ImageMetadata, *uefi.UEFI) {
	// Either image or parsedCache should not be nil
	if image == nil {
		image = parsedCache.Buf()
	}

	result := models.ImageMetadata{
		Size:  uint64(len(image)),
		TSAdd: time.Now(),
	}
	if filename != "" {
		result.Filename = sql.NullString{Valid: true, String: filename}
	}

	result = setHashes(ctx, result, image)
	return a.trySetFWVersionAndDate(ctx, result, image, parsedCache)
}

func (a *AnalyzerFirmwaresAccessor) trySetFWVersionAndDate(
	ctx context.Context,
	meta models.ImageMetadata,
	image []byte,
	parsedCache *uefi.UEFI,
) (models.ImageMetadata, *uefi.UEFI) {
	span, ctx := tracer.StartChildSpanFromCtx(ctx, "trySetFWVersionAndDate")
	defer span.Finish()
	log := logger.FromCtx(ctx)
	_meta, releaseFn, _ := a.storage.FindOne(ctx, firmwarestorage.FindFilter{
		ImageID: &meta.ImageID,
	})
	if releaseFn != nil {
		releaseFn()
	}
	if _meta != nil {
		return *_meta, parsedCache
	}

	usingCachedParsedUEFI := parsedCache != nil
	if parsedCache == nil {
		var err error
		span, _ := tracer.StartChildSpanFromCtx(ctx, "trySetFWVersionAndDate-Parse")
		parsedCache, err = uefi.Parse(image, true)
		span.Finish()
		if err != nil {
			log.Errorf("unable to parse the image: %v", err)
			return meta, nil
		}
	}

	if parsedCache == nil {
		return meta, nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		span, _ := tracer.StartChildSpanFromCtx(ctx, "trySetFWVersionAndDate-stableHash")
		defer span.Finish()
		var err error
		meta.HashStable, err = types.NewImageStableHash(parsedCache)
		if err != nil {
			log.Errorf("unable to calculate the stable hash of the image: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		span, ctx := tracer.StartChildSpanFromCtx(ctx, "trySetFWVersionAndDate-versionAndDate")
		defer span.Finish()
		dmiTable, err := dmidecode.DMITableFromFirmware(parsedCache)
		if err != nil && usingCachedParsedUEFI {
			// The cached parsed uefi.UEFI might be parsed without decompression,
			// while it might be required for this specific image (to extract SMBIOS data).
			// Trying again, but explicitly requiring decompression:
			//
			// TODO: Check if this actually might help before wasting
			//       CPU resourcing here. For example the image may
			//       not have compressed areas, or may actually already
			//       be decompressed.
			span, _ := tracer.StartChildSpanFromCtx(ctx, "trySetFWVersionAndDate-versionAndDate-Parse")
			defer span.Finish()
			parsedCache, err = uefi.Parse(image, true)
			span.Finish()
			if err != nil {
				log.Errorf("unable to parse image: %v", err)
				return
			}
			dmiTable, err = dmidecode.DMITableFromFirmware(parsedCache)
		}
		if err != nil {
			log.Errorf("unable to get SMBIOS info: %v", err)
			return
		}
		biosInfo := dmiTable.BIOSInfo()

		meta.FirmwareVersion = sql.NullString{
			String: biosInfo.Version,
			Valid:  true,
		}
		meta.FirmwareDateString = sql.NullString{
			String: biosInfo.ReleaseDate,
			Valid:  true,
		}
	}()
	wg.Wait()

	return meta, parsedCache
}

func (a *AnalyzerFirmwaresAccessor) getWrapper(
	ctx context.Context,
	getFn func(ctx context.Context) ([]byte, *models.ImageMetadata, *uefi.UEFI, *dmidecode.BIOSInfo, error),
	methodName string,
	rawCacheKey ...any,
) (retBlob analysis.Blob, retErr error) {
	span, ctx := tracer.StartChildSpanFromCtx(ctx, fmt.Sprintf("FW-%s-wrapper", methodName))
	defer span.Finish()

	if rawCacheKey != nil {
		cacheKey, err := objhash.Build(append([]any{methodName}, rawCacheKey...))
		if err != nil {
			logger.FromCtx(ctx).Errorf("unable to calculate a cache key for %#+v: %v", rawCacheKey, err)
		} else {
			unlocker := a.cacheSingleOp.Lock(cacheKey)
			defer unlocker.Unlock()

			if unlocker.UserData != nil {
				result := unlocker.UserData.(analyzerFirmwaresAccessorResult)
				return result.Blob, result.Error
			}

			a.cacheLocker.Lock()
			if result, ok := a.cache[cacheKey]; ok {
				a.cacheLocker.Unlock()
				return result.Blob, result.Error
			}
			a.cacheLocker.Unlock()

			defer func() {
				a.cacheLocker.Lock()
				defer a.cacheLocker.Unlock()
				a.cache[cacheKey] = analyzerFirmwaresAccessorResult{
					Blob:  retBlob,
					Error: retErr,
				}
			}()
		}
	}

	image, meta, parsed, biosInfo, err := getFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get the firmware: %w", err)
	}

	a.saveImageAsync(ctx, *meta, image)

	blob := &AnalyzerFirmwareAccessor{
		ImageID: meta.ImageID,
	}
	blob.Init(image, parsed, biosInfo)

	return blob, nil
}

func biosInfoFromMeta(meta *models.ImageMetadata) *dmidecode.BIOSInfo {
	if meta == nil {
		return nil
	}

	if !meta.FirmwareDateString.Valid || !meta.FirmwareVersion.Valid {
		return nil
	}

	// TODO: add the rest of the BIOSInfo fields to the database
	return &dmidecode.BIOSInfo{
		Version:     meta.FirmwareVersion.String,
		ReleaseDate: meta.FirmwareDateString.String,
	}
}

// GetByBlob implements analyzerinput.FirmwaresAccessor (see the description of AnalyzerFirmwaresAccessor).
func (a *AnalyzerFirmwaresAccessor) GetByBlob(ctx context.Context, image []byte) (analysis.Blob, error) {
	span, ctx := tracer.StartChildSpanFromCtx(ctx, "FW-GetByBlob")
	defer span.Finish()
	meta := models.ImageMetadata{
		Size:  uint64(len(image)),
		TSAdd: time.Now(),
	}
	meta = setHashes(ctx, meta, image)
	return a.getWrapper(ctx, func(ctx context.Context) ([]byte, *models.ImageMetadata, *uefi.UEFI, *dmidecode.BIOSInfo, error) {
		meta, parsed := a.trySetFWVersionAndDate(ctx, meta, image, nil)
		return image, &meta, parsed, biosInfoFromMeta(&meta), nil
	}, "GetByBlob", meta.ImageID)
}

// GetByID implements analyzerinput.FirmwaresAccessor (see the description of AnalyzerFirmwaresAccessor).
func (a *AnalyzerFirmwaresAccessor) GetByID(ctx context.Context, imageID types.ImageID) (analysis.Blob, error) {
	return a.getWrapper(ctx, func(ctx context.Context) ([]byte, *models.ImageMetadata, *uefi.UEFI, *dmidecode.BIOSInfo, error) {
		image, meta, err := a.storage.Get(ctx, imageID)
		return image, meta, nil, biosInfoFromMeta(meta), err
	}, "GetByID", imageID)
}

// GetByVersionAndDate implements analyzerinput.FirmwaresAccessor (see the description of AnalyzerFirmwaresAccessor).
func (a *AnalyzerFirmwaresAccessor) GetByVersionAndDate(
	ctx context.Context,
	firmwareVersion, firmwareDateString string,
) (analysis.Blob, error) {
	return a.getWrapper(ctx, func(ctx context.Context) ([]byte, *models.ImageMetadata, *uefi.UEFI, *dmidecode.BIOSInfo, error) {
		fw, err := getRTPFirmware(
			ctx,
			a.rtpFW,
			firmwareVersion,
			firmwareDateString,
			a.targetModelFamilyID,
			a.firmwareExpectedEvaluationStatus,
			types.CachingPolicyDefault,
		)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("unable to get the RTP Firmware: %w", err)
		}
		filename := ""
		if fw.Metadata.TarballFilename != nil {
			filename = *fw.Metadata.TarballFilename
		}
		meta, parsed := a.metaByImage(ctx, fw.ImageFile.Data, fw.ParsedCache, filename)
		return fw.ImageFile.Data, &meta, parsed, biosInfoFromMeta(&meta), err
	}, "GetByVersionAndDate", firmwareVersion, firmwareDateString)
}

// GetByFilename implements analyzerinput.FirmwaresAccessor (see the description of AnalyzerFirmwaresAccessor).
func (a *AnalyzerFirmwaresAccessor) GetByFilename(ctx context.Context, filename string) (analysis.Blob, error) {
	return a.getWrapper(ctx, func(ctx context.Context) ([]byte, *models.ImageMetadata, *uefi.UEFI, *dmidecode.BIOSInfo, error) {
		origFirmwareBytes, _, err := a.originalFirmwareStorage.DownloadByFilename(ctx, filename)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("unable to download the original firmware by filename '%s': %w", filename, err)
		}
		meta, parsed := a.metaByImage(ctx, origFirmwareBytes, nil, filename)
		return origFirmwareBytes, &meta, parsed, biosInfoFromMeta(&meta), nil
	}, "GetByFilename", filename)
}

// GetByEverstoreHandle implements analyzerinput.FirmwaresAccessor (see the description of AnalyzerFirmwaresAccessor).
func (a *AnalyzerFirmwaresAccessor) GetByEverstoreHandle(ctx context.Context, handle string) (analysis.Blob, error) {
	return a.getWrapper(ctx, func(ctx context.Context) ([]byte, *models.ImageMetadata, *uefi.UEFI, *dmidecode.BIOSInfo, error) {
		firmwareImageRaw, originalFilename, err := a.originalFirmwareStorage.DownloadByEverstoreHandle(ctx, handle)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("unable to download the original firmware by everstore handle '%s': %w", handle, err)
		}

		fw, filename, err := firmwarestorage.ExtractFirmwareImage(ctx, originalFilename, firmwareImageRaw)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("unable to extract the original firmware: %w", err)
		}

		meta, _ := a.metaByImage(ctx, nil, fw, filename)
		return fw.Buf(), &meta, fw, biosInfoFromMeta(&meta), nil
	}, "GetByEverstoreHandle", handle)
}

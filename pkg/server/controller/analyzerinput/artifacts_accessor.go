package analyzerinput

import (
	"context"
	"fmt"
	"sync"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/typeconv"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/lockmap"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// FirmwareImageFilename refers to the either firmware filename in the RTP table or one of the options below
type FirmwareImageFilename string

// ArtifactsAccessor is a helper that unifies access to the input artifacts
type ArtifactsAccessor interface {
	GetFirmware(ctx context.Context, artIdx int) (analysis.Blob, error)
	GetRegisters(ctx context.Context, artIdx int) (registers.Registers, error)
	GetTPMDevice(ctx context.Context, artIdx int) (tpmdetection.Type, error)
	GetTPMEventLog(ctx context.Context, artIdx int) (*tpmeventlog.TPMEventLog, error)
	GetPCR(ctx context.Context, artIdx int) ([]byte, uint32, error)
	GetMeasurementsFlow(ctx context.Context, inputIdx int) (types.BootFlow, error)
}

// FirmwareImage combines firmware image metadata and data together.
type FirmwareImage struct {
	Meta    models.ImageMetadata
	Content []byte
}

// FirmwaresAccessor abstracts obtaining firmware image.
//
// It provides an analysis.Blob given different data (in different methods).
type FirmwaresAccessor interface {
	GetByBlob(ctx context.Context, content []byte) (analysis.Blob, error)
	GetByID(ctx context.Context, imageID types.ImageID) (analysis.Blob, error)
	GetByVersion(ctx context.Context, firmwareVersion string) (analysis.Blob, error)
}

type getFirmwareResult struct {
	FirmwareAccessor analysis.Blob
	Error            error
}

type artifactsAccessor struct {
	firmwaresAccessor FirmwaresAccessor
	artifacts         []afas.Artifact

	singleOpLock *lockmap.LockMap
	cache        map[int]getFirmwareResult
	cacheLocker  sync.Mutex
}

// NewArtifactsAccessor creates a new ArtifactsAccessor object
//
// Is not re-usable between different calls of Analyze method!
func NewArtifactsAccessor(
	artifacts []afas.Artifact,
	firmwaresAccessor FirmwaresAccessor,
) (ArtifactsAccessor, error) {
	if firmwaresAccessor == nil {
		return nil, fmt.Errorf("firmwareImageAccessor is nil")
	}
	return &artifactsAccessor{
		firmwaresAccessor: firmwaresAccessor,
		artifacts:         artifacts,
		singleOpLock:      lockmap.NewLockMap(),
		cache:             make(map[int]getFirmwareResult),
	}, nil
}

func (a *artifactsAccessor) checkIndex(artIdx int) error {
	if artIdx < 0 || artIdx >= len(a.artifacts) {
		return fmt.Errorf("input index '%d' is out of range [0: %d)", artIdx, len(a.artifacts))
	}
	return nil
}

func (a *artifactsAccessor) GetFirmware(
	ctx context.Context,
	artIdx int,
) (retFirmwareAccessor analysis.Blob, retError error) {
	log := logger.FromCtx(ctx)
	if err := a.checkIndex(artIdx); err != nil {
		return nil, err
	}

	key := objhash.MustBuild("getFirmwareImage", artIdx)
	l := a.singleOpLock.Lock(key)
	defer l.Unlock()

	a.cacheLocker.Lock()
	cachedResult, ok := a.cache[artIdx]
	a.cacheLocker.Unlock()
	if ok {
		return cachedResult.FirmwareAccessor, cachedResult.Error
	}

	defer func() {
		a.cacheLocker.Lock()
		defer a.cacheLocker.Unlock()
		cacheEntry := getFirmwareResult{
			FirmwareAccessor: retFirmwareAccessor,
			Error:            retError,
		}
		a.cache[artIdx] = cacheEntry
	}()

	var (
		firmwareAccessor analysis.Blob
		err              error
	)

	artifact := a.artifacts[artIdx]
	switch {
	case artifact.IsSetFwImage():
		fwImage := artifact.GetFwImage()

		switch {
		case fwImage.IsSetBlob():
			blob := fwImage.GetBlob()
			var image []byte
			image, err = helpers.Decompress(blob.GetBlob(), blob.GetCompression())
			if err != nil {
				err = fmt.Errorf("failed to decompress image for artifact '%d': %w", artIdx, err)
			} else {
				firmwareAccessor, err = a.firmwaresAccessor.GetByBlob(ctx, image)
			}
		case fwImage.IsSetManifoldID():
			firmwareAccessor, err = a.firmwaresAccessor.GetByID(ctx, types.NewImageIDFromBytes(fwImage.GetManifoldID()))
		case fwImage.IsSetFwVersion():
			firmwareVersionInfo := fwImage.GetFwVersion()
			firmwareAccessor, err = a.firmwaresAccessor.GetByVersion(
				ctx,
				firmwareVersionInfo.GetVersion(),
			)
			if err != nil {
				log.Errorf("Failed to get firmware image of version '%s': %v", firmwareVersionInfo.GetVersion(), err)
			}
		default:
			err = fmt.Errorf("not supported firmware image type for artifact '%d'", artIdx)
		}
	default:
		err = fmt.Errorf("unexpected artifact's '%d' type for obtaining firmware image", artIdx)
	}
	if err != nil {
		log.Errorf("Failed to get an image: %v", err)
		return nil, err
	}
	if firmwareAccessor == nil {
		err := fmt.Errorf("internal error: firmware is nil, but no error")
		log.Errorf("%v", err)
		return nil, err
	}

	return firmwareAccessor, nil
}

func (a *artifactsAccessor) GetRegisters(ctx context.Context, inputIdx int) (registers.Registers, error) {
	if err := a.checkIndex(inputIdx); err != nil {
		return nil, err
	}

	artifact := a.artifacts[inputIdx]
	if !artifact.IsSetStatusRegisters() {
		return nil, fmt.Errorf("unexpected artifact's '%d' type for obtaining status registers", inputIdx)
	}
	// should one cache that?
	return typeconv.FromThriftRegisters(artifact.GetStatusRegisters())
}

func (a *artifactsAccessor) GetTPMDevice(ctx context.Context, inputIdx int) (tpmdetection.Type, error) {
	if err := a.checkIndex(inputIdx); err != nil {
		return tpmdetection.TypeNoTPM, err
	}

	artifact := a.artifacts[inputIdx]
	if !artifact.IsSetTPMDevice() {
		return tpmdetection.TypeNoTPM, fmt.Errorf("unexpected artifact's '%d' type for obtaining TPM device", inputIdx)
	}
	return typeconv.FromThriftTPMType(artifact.GetTPMDevice())
}

func (a *artifactsAccessor) GetTPMEventLog(ctx context.Context, inputIdx int) (*tpmeventlog.TPMEventLog, error) {
	if err := a.checkIndex(inputIdx); err != nil {
		return nil, err
	}

	artifact := a.artifacts[inputIdx]
	if !artifact.IsSetTPMEventLog() {
		return nil, fmt.Errorf("unexpected artifact's '%d' type for obtaining TPM eventlog", inputIdx)
	}
	// should one cache that?
	return typeconv.FromThriftTPMEventLog(artifact.GetTPMEventLog()), nil
}

func (a *artifactsAccessor) GetPCR(ctx context.Context, inputIdx int) ([]byte, uint32, error) {
	if err := a.checkIndex(inputIdx); err != nil {
		return nil, 0, err
	}
	artifact := a.artifacts[inputIdx]
	if !artifact.IsSetPcr() {
		return nil, 0, fmt.Errorf("unexpected artifact's '%d' type for obtaining PCR", inputIdx)
	}
	if artifact.Pcr.GetIndex() < 0 {
		return nil, 0, fmt.Errorf("invalid artifact's '%d' PCR index: '%d'", inputIdx, artifact.Pcr.GetIndex())
	}
	return artifact.Pcr.GetValue(), uint32(artifact.Pcr.GetIndex()), nil
}

func (a *artifactsAccessor) GetMeasurementsFlow(ctx context.Context, inputIdx int) (types.BootFlow, error) {
	if err := a.checkIndex(inputIdx); err != nil {
		return types.BootFlow{}, err
	}
	artifact := a.artifacts[inputIdx]
	if !artifact.IsSetMeasurementsFlow() {
		return types.BootFlow{}, fmt.Errorf("unexpected artifact's '%d' type for obtaining measurements flow", inputIdx)
	}
	flow, err := typeconv.FromThriftFlow(artifact.GetMeasurementsFlow())
	return types.BootFlow(flow), err
}

type firmwareImageArtifact struct {
	image     []byte
	imageHash objhash.ObjHash
	err       error
}

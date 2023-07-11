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
package analyzerinput

import (
	"context"
	"fmt"
	"sync"

	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/if/typeconv"
	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/lockmap"
	"github.com/immune-gmbh/attestation-sdk/pkg/objhash"
	"github.com/immune-gmbh/attestation-sdk/pkg/server/controller/helpers"
	"github.com/immune-gmbh/attestation-sdk/pkg/storage/models"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// FirmwareImageFilename refers to the either firmware filename in the orig firmware table or one of the options below
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
	Meta    models.FirmwareImageMetadata
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
		case fwImage.IsSetBlobStorageKey():
			firmwareAccessor, err = a.firmwaresAccessor.GetByID(ctx, types.NewImageIDFromBytes([]byte(fwImage.GetBlobStorageKey())))
		case fwImage.IsSetFirmwareVersion():
			firmwareAccessor, err = a.firmwaresAccessor.GetByVersion(ctx, fwImage.GetFirmwareVersion().Version)
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

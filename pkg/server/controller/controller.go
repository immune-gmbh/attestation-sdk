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
	"fmt"
	"sync"
	"time"

	css_errors "github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/logger"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"

	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/if/generated/device"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers"
	"github.com/immune-gmbh/attestation-sdk/pkg/firmwaredb"
)

func init() {
	// We do not modify images, so we can enable an appropriate optimizations.
	fianoUEFI.ReadOnly = true

	// We do not modify images and we are not interested in decompressed data,
	// so we can enable an appropriate optimization.
	fianoUEFI.DisableDecompression = true

	// Ignore "erase polarity conflict" error.
	fianoUEFI.SuppressErasePolarityError = true
}

type noCopy sync.Locker

// Controller implement the high-level logic of the firmware-analysis service.
type Controller struct {
	noCopy noCopy

	Context                   context.Context
	ContextCancel             context.CancelFunc
	FirmwareStorage           Storage
	DeviceGetter              DeviceGetter
	OriginalFWDB              firmwaredb.DB
	OriginalFWImageRepository originalFWImageRepository
	analyzersRegistry         *analyzers.Registry
	analysisDataCalculator    analysisDataCalculatorInterface

	closedSignal       chan struct{}
	activeGoroutinesWG sync.WaitGroup
}

func New(
	ctx context.Context,
	firmwareStorage Storage,
	origFirmwareDB firmwaredb.DB,
	origFirmwareRepo originalFWImageRepository,
	analysisDataCalculator analysisDataCalculatorInterface,
	deviceGetter DeviceGetter,
	apiCachePurgeTimeout time.Duration,
) (*Controller, error) {
	ctx = beltctx.WithField(ctx, "module", "controller")

	analyzersRegistry, err := analyzers.NewRegistryWithKnownAnalyzers()
	if err != nil {
		return nil, fmt.Errorf("failed to create analyzers registry: %w", err)
	}

	ctrl := &Controller{
		FirmwareStorage:           firmwareStorage,
		DeviceGetter:              deviceGetter,
		OriginalFWDB:              origFirmwareDB,
		OriginalFWImageRepository: origFirmwareRepo,
		analyzersRegistry:         analyzersRegistry,
		analysisDataCalculator:    analysisDataCalculator,

		closedSignal: make(chan struct{}),
	}
	ctrl.Context, ctrl.ContextCancel = context.WithCancel(ctx)

	ctrl.launchAsync(ctrl.Context, func(ctx context.Context) {
		ctrl.updateCacheLoop(ctx, apiCachePurgeTimeout)
	})
	return ctrl, nil
}

func (ctrl *Controller) updateCacheLoop(
	ctx context.Context,
	apiCachePurgeTimeout time.Duration,
) {
	apiCachePurgeTicker := time.NewTicker(apiCachePurgeTimeout)
	defer apiCachePurgeTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-apiCachePurgeTicker.C:
			ctrl.purgeAPICache()
		}
	}
}

func (ctrl *Controller) purgeAPICache() {
	ctx := ctrl.Context

	logger.FromCtx(ctx).Infof("purge controller API cache")
	// TODO: purge any cache
}

// getHostInfo tries to get full information about the host being analyzed.
// If request is being made from the host that is being analyzed, a host can provide information about itself in thrift input structure.
// But that information may not be full
func (ctrl *Controller) getHostInfo(
	ctx context.Context,
	requestHostInfo *afas.HostInfo,
) (*afas.HostInfo, *device.Device) {
	if requestHostInfo == nil {
		return nil, nil
	}

	log := logger.FromCtx(ctx)

	resultHostInfo := *requestHostInfo
	device := func() *device.Device {
		if resultHostInfo.IsClientHostAnalyzed {
			hostname, _ := ExtractHostnameFromCtx(ctx)
			if len(hostname) > 0 {
				log.Debugf("detected TLS identity hostname: %s", hostname)
				device, err := ctrl.DeviceGetter.GetDeviceByHostname(hostname)
				if err == nil {
					return device
				}
				log.Warnf("failed to get device info for %s: %v", hostname, err)
			}
		}
		if resultHostInfo.AssetID != nil {
			device, err := ctrl.DeviceGetter.GetDeviceByAssetID(*resultHostInfo.AssetID)
			if err == nil {
				return device
			}
			log.Warnf("failed to get device info by asset id %d: %v", *resultHostInfo.AssetID, err)
		}

		if resultHostInfo.Hostname != nil {
			device, err := ctrl.DeviceGetter.GetDeviceByHostname(*resultHostInfo.Hostname)
			if err == nil {
				return device
			}
			log.Warnf("failed to get device info for %s: %v", *resultHostInfo.Hostname, err)
		}
		return nil
	}()
	if device != nil {
		enrichHostInfo(ctx, device, false, &resultHostInfo)
	}
	return &resultHostInfo, device
}

// Close stops the Controller and blocks until all goroutines from launchAsync
// rejoin.
//
// Invariants:
//  1. Close will wait for goroutines to rejoin before invalidating any state
//  2. After Close has been called, launchAsync will fail with context.Canceled
//  3. Goroutines MUST NOT call Close
//  4. Goroutines MUST return promptly when their context is cancelled
func (ctrl *Controller) Close() error {
	ctrl.ContextCancel()
	ctrl.activeGoroutinesWG.Wait()

	err := css_errors.MultiError{}
	err.Add(
		ctrl.FirmwareStorage.Close(),
	)
	return err.ReturnValue()
}

// launchAsync starts the given function in the background. The context passed
// to the function will be cancelled with the call to ctrl.Close(). If the
// controller has already received a call to Close, then this function will
// return the cancellation error (in this case most likely context.Canceled).
//
// Goroutines launched this way MUST NOT call Controller.Close, because it would
// DEADLOCK. See Close for other invariants.
func (ctrl *Controller) launchAsync(ctx context.Context, f func(ctx context.Context)) error {
	// Need to do this first to prevent another thread entering Close() between
	// the `if` and the `go` from returning.
	ctrl.activeGoroutinesWG.Add(1)
	if ctx.Err() != nil {
		ctrl.activeGoroutinesWG.Done()
		return ctx.Err()
	}

	// If another thread calls Close before this goroutine starts, the latter
	// will spin up with an already cancelled context and return promptly, but
	// the Close thread will still wait for it.
	go func() {
		defer ctrl.activeGoroutinesWG.Done()
		f(ctx)
	}()

	return nil
}

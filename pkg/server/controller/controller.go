package controller

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"lukechampine.com/blake3"

	css_errors "github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/logger"
	lru "github.com/hashicorp/golang-lru"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarestorage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/lockmap"
	controllertypes "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

func init() {
	// We do not modify images, so we can enable an appropriate optimizations.
	fianoUEFI.ReadOnly = true

	// We do not modify images and we are not interested in decompressed data,
	// so we can enable an appropriate optimization.
	fianoUEFI.DisableDecompression = true

	// Ignore "erase polarity conflict" error to be able to parse Zion-2S images.
	fianoUEFI.SuppressErasePolarityError = true
}

// Controller implement the high-level logic of the firmware-analysis service.
type Controller struct {
	Context                context.Context
	ContextCancel          context.CancelFunc
	Storage                storageInterface
	FirmwareStorage        originalFirmwareStorage
	analyzersRegistry      *analyzers.Registry
	analysisDataCalculator analysisDataCalculatorInterface

	DiffFirmwareCache     *lru.TwoQueueCache
	DiffFirmwareCacheLock *lockmap.LockMap
	UEFIParseLock         *lockmap.LockMap

	activeGoroutinesWG sync.WaitGroup
}

// New returns an instance of Controller.
func New(
	ctx context.Context,
	apiCachePurgeTimeout time.Duration,
	storageCacheSize uint64,
	diffFirmwareCacheSize int,
	dataCalcCacheSize int,
	rdbmsURL string,
) (*Controller, error) {
	log := logger.FromCtx(ctx)
	manifoldClient, err := getManifoldClient(manifoldBucket, manifoldAPIKey)
	if err != nil {
		return nil, ErrInitStorage{Err: fmt.Errorf("unable to initialize manifold client: %w", err)}
	}

	storCache, err := newStorageCache(storageCacheSize)
	if err != nil {
		log.Errorf("unable to initialize storage cache: %v", err)
	}

	stor, err := storage.NewStorage(rdbmsURL, manifoldClient, storCache, log.WithField("module", "storage"))
	if err != nil {
		return nil, ErrInitStorage{Err: err}
	}

	serfClient, err := serf.NewClient(tierSeRF)
	if err != nil {
		return nil, ErrInitSeRFClient{Err: err}
	}

	tagStoreClient, err := tag.NewClient()
	if err != nil {
		return nil, ErrGetTagStore{Err: err}
	}

	rtpDB, err := rtpdb.GetDBRW()
	if err != nil {
		return nil, fmt.Errorf("unable to get a DB-client to RTP table: %w", err)
	}
	firmwareStorage := firmwarestorage.NewFirmwareStorage("FirmwareAnalyzer")

	rtpfw, err := rtpfw.New(ctx, rtpDB, firmwareStorage, tagStoreClient, rtpfwCacheSize, rtpfwCacheEvictionTimeout,
		types.DBIEnabledTag, types.DBIDisabledTag, types.DCDEnabledTag, types.DCDDisabledTag, types.PCRValidated,
		types.PCR0SHA1Tag, types.PCR0SHA256Tag,
	)
	if err != nil {
		return nil, ErrInitRTPFW{Err: err}
	}

	rfeClient, err := rfe.New()
	if err != nil {
		return nil, ErrInitRFE{Err: err}
	}

	dataCalculator, err := analysis.NewDataCalculator(dataCalcCacheSize)
	if err != nil {
		return nil, ErrInitDataCalculator{Err: err}
	}
	controllertypes.OverrideValueCalculators(dataCalculator)

	return newInternal(
		ctx,
		stor,
		firmwareStorage,
		rtpfw,
		newRTPDBReader(rtpDB),
		dataCalculator,
		apiCachePurgeTimeout,
		diffFirmwareCacheSize,
	)
}

func newInternal(
	ctx context.Context,
	storage storageInterface,
	firmwareStorage originalFirmwareStorage,
	analysisDataCalculator analysisDataCalculatorInterface,
	apiCachePurgeTimeout time.Duration,
	diffFirmwareCacheSize int,
) (*Controller, error) {
	if apiCachePurgeTimeout > rtpfwCacheEvictionTimeout {
		return nil, fmt.Errorf("API cache purge timeout '%v' is larger than rtp firmware cache timeout'%v'",
			apiCachePurgeTimeout,
			rtpfwCacheEvictionTimeout,
		)
	}

	ctx = beltctx.WithField(ctx, "module", "controller")

	diffFirmwareCache, err := lru.New2Q(diffFirmwareCacheSize)
	if err != nil {
		return nil, ErrInitCache{For: "DiffFirmware", Err: err}
	}

	reportHostConfigCache, err := lru.New2Q(reportHostConfigCacheSize)
	if err != nil {
		return nil, ErrInitCache{For: "ReportHostConfigCache", Err: err}
	}

	analyzersRegistry, err := analyzers.NewRegistryWithKnownAnalyzers()
	if err != nil {
		return nil, fmt.Errorf("failed to create analyzers registry: %w", err)
	}

	ctrl := &Controller{
		Storage:                storage,
		FirmwareStorage:        firmwareStorage,
		analyzersRegistry:      analyzersRegistry,
		analysisDataCalculator: analysisDataCalculator,

		DiffFirmwareCache:     diffFirmwareCache,
		DiffFirmwareCacheLock: lockmap.NewLockMap(),
		UEFIParseLock:         lockmap.NewLockMap(),
	}
	ctrl.Context, ctrl.ContextCancel = context.WithCancel(ctx)

	ctrl.launchAsync(ctrl.Context, func(ctx context.Context) {
		ctrl.updateCacheLoop(ctx, apiCachePurgeTimeout)
	})
	return ctrl, nil
}

func (ctrl *Controller) updateCacheLoop(ctx context.Context, apiCachePurgeTimeout time.Duration, rtpCacheUpdateTimeout time.Duration) {
	rtpUpdateTicker := time.NewTicker(rtpCacheUpdateTimeout)
	defer rtpUpdateTicker.Stop()

	apiCachePurgeTicker := time.NewTicker(apiCachePurgeTimeout)
	defer apiCachePurgeTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-apiCachePurgeTicker.C:
			ctrl.purgeAPICache()
		case <-rtpUpdateTicker.C:
			ctrl.updateRTPFWCache()
		}
	}
}

func (ctrl *Controller) updateRTPFWCache() {
	ctx := ctrl.Context
	log := logger.FromCtx(ctx)
	log.Infof("Update RTP cache")
	updated, err := ctrl.rtpfw.Update(ctx)
	if err != nil {
		log.Errorf("Failed to updated RTP table cache, err: %v", err)
		return
	}

	if updated {
		log.Infof("Clear cache diff firmware and calc pcr0 caches")
		ctrl.purgeAPICache()
	}
}

func (ctrl *Controller) purgeAPICache() {
	ctx := ctrl.Context

	logger.FromCtx(ctx).Infof("purge controller API cache")
	ctrl.DiffFirmwareCache.Purge()
	ctrl.ReportHostConfigCache.Purge()
}

func (ctrl *Controller) diffFirmwareCacheLoad() *lru.TwoQueueCache {
	return (*lru.TwoQueueCache)(atomic.LoadPointer((*unsafe.Pointer)((unsafe.Pointer)(&ctrl.DiffFirmwareCache))))
}

func uint64deref(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

// getRTPFirmware fallbacks to getting firmware for most production ready evaluation status firmware or/and modelID == 0
// if there is no RTP table entry for requested evaluationStatus
// This becomes helpful in case when evaluationStatus was determined incorrectly (for example because it was not updated in either RTP table or SERF)
func getRTPFirmware(
	ctx context.Context,
	rtpFW rtpfwInterface,
	firmwareVersion, firmwareDateString string,
	modelFamilyID *uint64,
	expectedEvaluationStatus sdf, //rtp.EvaluationStatus,
	cachingPolicy types.CachingPolicy,
) (rtpfw.Firmware, error) {
	log := logger.FromCtx(ctx)

	fw, err := rtpFW.GetFirmware(ctx, firmwareVersion, firmwareDateString, modelFamilyID, expectedEvaluationStatus, cachingPolicy)
	if err == nil || !errors.As(err, &rtpfw.ErrNotFound{}) {
		return fw, err
	}
	log.Warnf("No firmware found for '%s'/'%s'/'%s'/%d", firmwareVersion, firmwareDateString, expectedEvaluationStatus, uint64deref(modelFamilyID))
	if expectedEvaluationStatus != rtpfw.EvaluationStatusMostProductionReady {
		// We have not found a firmware with the expected evaluation status, so trying
		// to find a firmware with any evaluation status, but preferring the one
		// which is the closest to be production ready.
		//
		// See also: https://fburl.com/code/8di4o5ze
		log.Infof("Falling back to get firmare for the 'most production ready' evaluation status")
		fw, err = rtpFW.GetFirmware(ctx, firmwareVersion, firmwareDateString, modelFamilyID, rtpfw.EvaluationStatusMostProductionReady, cachingPolicy)
		if err == nil || !errors.As(err, &rtpfw.ErrNotFound{}) {
			return fw, err
		}
	}
	if modelFamilyID == nil {
		return fw, err
	}
	log.Infof("Falling back to get firmare to modelFamilyID == nil")
	fw, err = rtpFW.GetFirmware(ctx, firmwareVersion, firmwareDateString, nil, expectedEvaluationStatus, cachingPolicy)
	if err == nil || !errors.As(err, &rtpfw.ErrNotFound{}) {
		return fw, err
	}
	if expectedEvaluationStatus != rtpfw.EvaluationStatusMostProductionReady {
		log.Infof("Falling back to get firmare for 'most production ready' evaluation status and modelFamilyID == nil")
		fw, err = rtpFW.GetFirmware(ctx, firmwareVersion, firmwareDateString, nil, rtpfw.EvaluationStatusMostProductionReady, cachingPolicy)
		if err == nil || !errors.As(err, &rtpfw.ErrNotFound{}) {
			return fw, err
		}
	}
	return rtpfw.Firmware{}, err
}

// getHostInfo tries to get full information about the host being analyzed.
// If request is being made from the host that is being analyzed, a host can provide information about itself in thrift input structure.
// But that information may not be full
func (ctrl *Controller) getHostInfo(
	ctx context.Context,
	requestHostInfo *afas.HostInfo,
) (*afas.HostInfo, sdf /* *device.Device */) {
	if requestHostInfo == nil {
		return nil, nil
	}

	log := logger.FromCtx(ctx)

	resultHostInfo := *requestHostInfo
	serfDevice := func() sdf /* *device.Device */ {
		if resultHostInfo.IsClientHostAnalyzed {
			hostname, _ := ExtractHostnameFromCtx(ctx)
			if len(hostname) > 0 {
				log.Debugf("detected TLS identity hostname: %s", hostname)
				device, err := ctrl.SeRF.GetDeviceByName(hostname)
				if err == nil {
					return device
				}
				log.Warnf("failed to get SeRF info for %s: %v", hostname, err)
			}
		}
		if resultHostInfo.AssetID != nil {
			device, err := ctrl.SeRF.GetDeviceById(*resultHostInfo.AssetID)
			if err == nil {
				return device
			}
			log.Warnf("failed to get SeRF info by asset id %d: %v", *resultHostInfo.AssetID, err)
		}

		if resultHostInfo.Hostname != nil {
			device, err := ctrl.SeRF.GetDeviceByName(*resultHostInfo.Hostname)
			if err == nil {
				return device
			}
			log.Warnf("failed to get SeRF info for %s: %v", *resultHostInfo.Hostname, err)
		}
		return nil
	}()
	if serfDevice != nil {
		enrichHostInfo(ctx, serfDevice, false, &resultHostInfo)
	}
	return &resultHostInfo, serfDevice
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
		ctrl.Storage.Close(),
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

func (ctrl *Controller) parseUEFI(b []byte) (*uefi.UEFI, error) {
	// Preventing multiple concurrent parsing of the same image. Compute one and use everywhere, instead
	l := ctrl.UEFIParseLock.Lock(firmwareImageCacheKey(b))
	defer l.Unlock()

	if l.UserData != nil {
		// The value is already computed, just use it.
		return l.UserData.(*uefi.UEFI), nil
	}

	f, err := uefi.ParseUEFIFirmwareBytes(b)
	if err != nil {
		return nil, err
	}

	l.UserData = f
	return f, nil
}

func firmwareMetaCacheKey(imageMeta models.ImageMetadata) string {
	return firmwareCacheKey(imageMeta.HashSHA2_512, imageMeta.HashBlake3_512)
}

func firmwareImageCacheKey(b []byte) string {
	sha512Sum := sha512.Sum512(b)
	blake3Sum := blake3.Sum512(b)
	return firmwareCacheKey(sha512Sum[:], blake3Sum[:])
}

// For security reasons we do two different hashes (to avoid intentional
// collisions).
func firmwareCacheKey(sha512Sum, blake3Sum []byte) string {
	var resultCacheKey strings.Builder
	resultCacheKey.Write(sha512Sum[:])
	resultCacheKey.Write(blake3Sum[:])

	return resultCacheKey.String()
}

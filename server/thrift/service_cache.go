package thrift

import (
	"context"
	"sync"
	"time"
)

type serviceCache struct {
	statsExportCache      map[statsExportKey]*statsExportResult
	statsExportCacheMutex sync.Mutex
	gcLoopMutex           sync.Mutex
	gcLoopStopFunc        context.CancelFunc
	gcLazyCallCount       uint64
}

func newServiceCache() *serviceCache {
	return &serviceCache{
		statsExportCache: map[statsExportKey]*statsExportResult{},
	}
}

func (cache *serviceCache) Reset() {
	cache.stopGC()
	cache.resetCache()
}

func (cache *serviceCache) resetCache() {
	cache.statsExportCacheReset()
}

func (cache *serviceCache) stopGC() {
	cache.gcLoopMutex.Lock()
	defer cache.gcLoopMutex.Unlock()

	if cache.gcLoopStopFunc != nil {
		cache.gcLoopStopFunc()
		cache.gcLoopStopFunc = nil
	}
}

// lazyStartGCLoop starts a garbage collection loop, which automatically stops
// if nothing left to collect.
//
// This approach allows keeping `server` seemingly stateless: no knowledge
// about internal state is required (no Start/Stop/Close function is required
// to call).
func (cache *serviceCache) lazyStartGCLoop() {
	cache.gcLoopMutex.Lock()
	defer cache.gcLoopMutex.Unlock()
	cache.gcLazyCallCount++
	if cache.gcLoopStopFunc != nil {
		// is already running
		return
	}

	ctx, stopFn := context.WithCancel(context.Background())
	cache.gcLoopStopFunc = stopFn
	go func() {
		ticker := time.NewTicker(gcInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			cache.gcLoopMutex.Lock()
			callCount := cache.gcLazyCallCount
			cache.gcLoopMutex.Unlock()
			if cache.gc() {
				// still have work to do in next iterations, continue
				continue
			}
			// no work to do, but let's recheck if somebody added some while
			// we were gc()-ing:
			cache.gcLoopMutex.Lock()
			newCallCount := cache.gcLazyCallCount
			if newCallCount != callCount {
				// somebody added some work, continue
				cache.gcLoopMutex.Unlock()
				continue
			}

			// no work was added, nothing to gc() in next iterations, exit
			cache.gcLoopStopFunc = nil
			cache.gcLoopMutex.Unlock()
			return
		}
	}()
}

// gc removes non-needed data and returns true if something else is
// required to be removed in the future.
func (cache *serviceCache) gc() bool {
	return cache.statsExportCacheCleanup() != 0
}

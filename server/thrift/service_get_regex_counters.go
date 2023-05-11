package thrift

import (
	"context"
	"fmt"
	"time"

	"github.com/dlclark/regexp2"
	"libfb/go/stats/export"
)

const (
	cacheExpireAfter = time.Hour
)

type statsExportKey struct {
	MetricKey string
	Regexp    string
}

type statsExportResult struct {
	LastAccessTS time.Time
	Result       bool
}

// GetRegexCounters is an analog of FacebookBase.GetRegexCounters, but with
// memoization of regexp operations.
//
// See also "Summary" in D31053848.
func (svc *service) GetRegexCounters(ctx context.Context, regex string) (map[string]int64, error) {
	if svc.Stats == nil {
		return svc.Base.GetRegexCounters(ctx, regex)
	}
	defer svc.Cache.lazyStartGCLoop()

	// In this function we are trying to cache specifically results of
	// regexp MatchString calculations (which are hidden inside `willExport`
	// function below)

	re, err := regexp2.Compile(regex, regexp2.None)
	if err != nil {
		return nil, fmt.Errorf("GetRegexCounters called with: %s: %w", regex, err)
	}

	query := export.NewQuery(export.Regexp(re))
	willExport := query.WillExportFunc()
	// `willExport` is effectively `re.MatchString` here.

	svc.Cache.statsExportCacheMutex.Lock()
	defer svc.Cache.statsExportCacheMutex.Unlock()

	now := time.Now()
	result := map[string]int64{}
	for k, v := range svc.Stats.GetInts() {
		cacheKey := statsExportKey{
			MetricKey: k,
			Regexp:    regex,
		}

		cache := svc.Cache.statsExportCache[cacheKey]
		if cache == nil {
			shouldExport := willExport(k) // equivalent of: shouldExport := re.MatchString(k)
			cache = &statsExportResult{
				LastAccessTS: now,
				Result:       shouldExport,
			}
			svc.Cache.statsExportCache[cacheKey] = cache
		} else {
			cache.LastAccessTS = now
		}

		if cache.Result {
			result[k] = v
		}
	}

	return result, nil
}

func (cache *serviceCache) statsExportCacheCleanup() (entriesLeft uint) {
	cache.statsExportCacheMutex.Lock()
	defer cache.statsExportCacheMutex.Unlock()

	now := time.Now()
	for k, c := range cache.statsExportCache {
		if !c.LastAccessTS.Add(cacheExpireAfter).Before(now) {
			continue
		}
		delete(cache.statsExportCache, k)
	}

	return uint(len(cache.statsExportCache))
}

func (cache *serviceCache) statsExportCacheReset() {
	cache.statsExportCacheMutex.Lock()
	defer cache.statsExportCacheMutex.Unlock()
	for k := range cache.statsExportCache {
		delete(cache.statsExportCache, k)
	}
}

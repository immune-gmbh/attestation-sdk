package controller

import (
	"context"
	"time"

	"github.com/dgraph-io/ristretto"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
)

const (
	storageCacheItemSizeLimit = 64 * (1 << 20) // 64MiB
)

type storageCache struct {
	cache *ristretto.Cache
}

var _ storage.Cache = (*storageCache)(nil)

func newStorageCache(memoryLimit uint64) (*storageCache, error) {
	cfg := &ristretto.Config{
		NumCounters: 1000,
		MaxCost:     int64(memoryLimit),
		BufferItems: 64,
		Metrics:     false,
	}
	cache, err := ristretto.NewCache(cfg)
	if err != nil {
		return nil, err
	}
	return &storageCache{
		cache: cache,
	}, nil
}

func (c *storageCache) Get(ctx context.Context, objKey objhash.ObjHash) any {
	obj, _ := c.cache.Get(string(objKey[:]))
	return obj
}

func (c *storageCache) Set(ctx context.Context, objKey objhash.ObjHash, obj any, objectSize uint64) {
	b, ok := obj.([]byte)
	if !ok {
		// not supported, yet
		return
	}
	if len(b) > storageCacheItemSizeLimit {
		// too big object
		return
	}

	c.cache.SetWithTTL(string(objKey[:]), b, int64(len(b)), time.Minute*10)
}

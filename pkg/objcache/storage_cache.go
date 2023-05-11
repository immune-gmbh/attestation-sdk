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
package objcache

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

func New(memoryLimit uint64) (*storageCache, error) {
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

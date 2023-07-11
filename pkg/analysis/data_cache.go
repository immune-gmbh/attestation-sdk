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

package analysis

import (
	"reflect"
	"sync"

	"github.com/immune-gmbh/attestation-sdk/pkg/objhash"
)

// CachedValue represents a value stored in DataCache
type CachedValue struct {
	// TODO: consider replacing "reflect.Value" with just "any"
	Val    reflect.Value
	Issues []Issue
	Err    error
}

// DataCache represents an interface for a cache used in analysis package
type DataCache interface {
	// Get returns a cached object if found. inputHash could be nil, for cases when cache guarantees object uniqness for each type.
	// On of that cases is `uniqueTypeDataCache` that is used to store objects obtained for a single Analyser
	Get(t reflect.Type, inputHash *objhash.ObjHash) *CachedValue
	Set(t reflect.Type, inputHash objhash.ObjHash, val *CachedValue)
}

// NewDataCache creates a new multithreaded implementation of DataCache
func NewDataCache() DataCache {
	return newDataCache()
}

func newDataCache() *dataCache {
	return &dataCache{
		cache: make(map[reflect.Type]map[objhash.ObjHash]*CachedValue),
	}
}

type dataCache struct {
	rwlock sync.RWMutex
	cache  map[reflect.Type]map[objhash.ObjHash]*CachedValue
}

func (c *dataCache) Get(t reflect.Type, inputHash *objhash.ObjHash) *CachedValue {
	if inputHash == nil {
		return nil
	}

	c.rwlock.RLock()
	defer c.rwlock.RUnlock()

	typeValues, found := c.cache[t]
	if !found {
		return nil
	}
	return typeValues[*inputHash]
}

func (c *dataCache) Set(t reflect.Type, inputHash objhash.ObjHash, val *CachedValue) {
	if val == nil {
		return
	}

	c.rwlock.Lock()
	defer c.rwlock.Unlock()

	typeValues, found := c.cache[t]
	if !found {
		typeValues = make(map[objhash.ObjHash]*CachedValue)
		c.cache[t] = typeValues
	}
	typeValues[inputHash] = val
}

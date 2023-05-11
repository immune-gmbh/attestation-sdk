package analysis

import (
	"reflect"
	"sync"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
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

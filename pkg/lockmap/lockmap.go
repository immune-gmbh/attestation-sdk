package lockmap

import (
	"sync"
)

// LockMap is a naive implementation of locking by specified key.
type LockMap struct {
	globalLock sync.Mutex
	lockMap    map[interface{}]*Unlocker
}

// NewLockMap returns an instance of LockMap.
func NewLockMap() *LockMap {
	return &LockMap{
		lockMap: map[interface{}]*Unlocker{},
	}
}

// Lock locks the key.
func (m *LockMap) Lock(key interface{}) *Unlocker {
	// logic:
	// * global lock
	// * get or create the item
	// * global unlock
	// * increment the reference count of the item
	// * lock the item
	// * return the item
	//
	// The item will be removed if reference count will drop down to zero.
	// And it will be re-added back to the global map if the reference count
	// will be increased back to positive values.

	m.globalLock.Lock()

	if l := m.lockMap[key]; l != nil {
		if l.refCount == 0 {
			panic("LockMap contains released Unlocker")
		}
		l.refCount++
		m.globalLock.Unlock()
		l.locker.Lock()
		return l
	}

	l := &Unlocker{m: m, key: key, refCount: 1}
	m.lockMap[key] = l
	m.globalLock.Unlock()

	l.locker.Lock()
	return l
}

package lockmap

import (
	"sync"
)

// Unlocker provides method Unlock, which could be used to unlock the key.
type Unlocker struct {
	// UserData is a field for arbitrary data, which could be used by
	// external packages
	UserData interface{}

	// internal:
	locker   sync.Mutex
	key      interface{}
	m        *LockMap
	refCount int64
}

// Unlock releases the lock for the key.
func (l *Unlocker) Unlock() {
	l.locker.Unlock()
	l.refCountDec()
}

func (l *Unlocker) refCountDec() {
	l.m.globalLock.Lock()
	defer l.m.globalLock.Unlock()
	l.refCount--
	if l.refCount == 0 {
		delete(l.m.lockMap, l.key)
	}
}

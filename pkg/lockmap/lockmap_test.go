package lockmap

import (
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLockMap(t *testing.T) {
	m := NewLockMap()

	var wg sync.WaitGroup
	for i := 0; i < 10000; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()

			l := m.Lock(k)
			defer l.Unlock()

			// check nobody else will corrupt UserData:
			require.Nil(t, l.UserData)
			l.UserData = 1
			runtime.Gosched()
			require.NotNil(t, l.UserData)
			l.UserData = nil
		}(i % 1000)
	}

	wg.Wait()
	for i := 0; i < 10000; i++ {
		// Unlock() creates new routines, and we want all of them end,
		// before checking if m.lockMap is indeed empty
		runtime.Gosched()
	}
	require.Zero(t, len(m.lockMap))
}

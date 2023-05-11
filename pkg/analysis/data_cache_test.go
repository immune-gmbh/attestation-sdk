package analysis

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDataCache(t *testing.T) {
	cache := NewDataCache()
	require.NotNil(t, cache)

	v := reflect.ValueOf(10)
	hash := objhash.MustBuild(10)

	require.Nil(t, cache.Get(v.Type(), nil))
	require.Nil(t, cache.Get(v.Type(), &hash))

	putValue := &CachedValue{Val: v}
	cache.Set(v.Type(), hash, putValue)

	require.Equal(t, putValue, cache.Get(v.Type(), &hash))
	require.Nil(t, cache.Get(v.Type(), nil))
	require.Nil(t, cache.Get(reflect.TypeOf("dummy"), &hash))
}

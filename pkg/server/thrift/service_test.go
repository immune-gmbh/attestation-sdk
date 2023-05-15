package thrift

import (
	"fmt"
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller"

	"github.com/stretchr/testify/require"
)

func TestThriftExceptionsUnwrapping(t *testing.T) {
	t.Run("ErrFetchOrigFirmware", func(t *testing.T) {
		fetchErr := controller.NewErrFetchOrigFirmware("version", fmt.Errorf("dummy"))
		require.Equal(t, fetchErr.ThriftException(), unwrapException(fetchErr))
	})

	t.Run("ErrParseOrigFirmware", func(t *testing.T) {
		parseErr := controller.NewErrParseOrigFirmware("version", fmt.Errorf("dummy"))
		require.Equal(t, parseErr.ThriftException(), unwrapException(parseErr))
	})

	t.Run("ErrInvalidHostConfiguration", func(t *testing.T) {
		configErr := controller.NewErrInvalidHostConfiguration(fmt.Errorf("dummy"))
		require.Equal(t, configErr.ThriftException(), unwrapException(configErr))
	})
}

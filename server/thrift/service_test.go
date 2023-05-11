package thrift

import (
	"fmt"
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/server/controller"

	"github.com/stretchr/testify/require"
)

func TestThriftExceptionsUnwrapping(t *testing.T) {
	t.Run("ErrFetchOrigFirmware", func(t *testing.T) {
		fetchErr := controller.NewErrFetchOrigFirmware("version", "date", fmt.Errorf("dummy"))
		require.Equal(t, fetchErr.ThriftException(), unwrapException(fetchErr))
	})

	t.Run("ErrParseOrigFirmware", func(t *testing.T) {
		parseErr := controller.NewErrParseOrigFirmware("version", "date", fmt.Errorf("dummy"))
		require.Equal(t, parseErr.ThriftException(), unwrapException(parseErr))
	})

	t.Run("ErrInvalidHostConfiguration", func(t *testing.T) {
		configErr := controller.NewErrInvalidHostConfiguration(fmt.Errorf("dummy"))
		require.Equal(t, configErr.ThriftException(), unwrapException(configErr))
	})
}

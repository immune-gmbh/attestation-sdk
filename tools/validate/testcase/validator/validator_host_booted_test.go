package validator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostBootedValidator(t *testing.T) {
	t.Run("expected_not_booted_actual_not_booted", func(t *testing.T) {
		validator := NewExpectHostBootedUp(false)
		err := validator.Validate(context.Background(), &ValidationInfo{
			HostBooted: false,
		})
		require.NoError(t, err)
	})

	t.Run("expected_booted_actual_booted", func(t *testing.T) {
		validator := NewExpectHostBootedUp(true)
		err := validator.Validate(context.Background(), &ValidationInfo{
			HostBooted: true,
		})
		require.NoError(t, err)
	})

	t.Run("expected_not_booted_actual_booted", func(t *testing.T) {
		validator := NewExpectHostBootedUp(false)
		err := validator.Validate(context.Background(), &ValidationInfo{
			HostBooted: true,
		})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrHostBootedUp{})
		require.NotEmpty(t, err.Error())
	})

	t.Run("expected_booted_actual_not_booted", func(t *testing.T) {
		validator := NewExpectHostBootedUp(true)
		err := validator.Validate(context.Background(), &ValidationInfo{
			HostBooted: false,
		})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrHostFailedBootUp{})
		require.NotEmpty(t, err.Error())
	})
}

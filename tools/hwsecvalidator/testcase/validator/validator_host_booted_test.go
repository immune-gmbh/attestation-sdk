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

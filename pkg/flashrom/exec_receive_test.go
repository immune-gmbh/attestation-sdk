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
package flashrom

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockProcess struct {
	output []byte
	error  error
}

func (p *mockProcess) Output() ([]byte, error) {
	return p.output, p.error
}

func TestExecReceive(t *testing.T) {
	ctx := context.Background()

	t.Run("helloWorld", func(t *testing.T) {
		testCmd := "echo"
		testArg := "hello\nworld!"
		testOut := "unit\ntest"

		execCount := 0
		f := &flashrom{
			overrideExecCommandFunc: func(ctx context.Context, name string, arg ...string) process {
				execCount++
				require.Equal(t, testCmd, name)
				require.Len(t, arg, 2)
				require.Equal(t, testArg, arg[0])
				require.NotEqual(t, outputPathArgument, arg[1])
				err := os.WriteFile(arg[1], []byte(testOut), 0000)
				require.NoError(t, err)
				return &mockProcess{output: []byte(arg[0])}
			},
		}

		output, err := f.execReceive(ctx, testCmd, testArg, outputPathArgument)
		require.Equal(t, 1, execCount)
		require.NoError(t, err)
		require.Equal(t, testOut, string(output))
	})

	t.Run("execErr", func(t *testing.T) {
		mockedProcess := &mockProcess{
			output: make([]byte, 1),
			error:  errors.New("unit-test"),
		}

		f := &flashrom{
			overrideExecCommandFunc: func(ctx context.Context, name string, arg ...string) process {
				return mockedProcess
			},
		}

		output, err := f.execReceive(ctx, "")
		require.Error(t, err)
		require.Nil(t, output)
		require.True(t, errors.Is(err, mockedProcess.error), fmt.Sprintf("%T:%v is not %T:%v", err, err, mockedProcess.error, mockedProcess.error))
	})
}

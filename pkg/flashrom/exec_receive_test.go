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

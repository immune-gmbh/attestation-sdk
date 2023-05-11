//go:build linux && integration
// +build linux,integration

package flashrom

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIntegrationExecReceiveTimeout(t *testing.T) {
	startTime := time.Now()
	ctx, _ := context.WithTimeout(context.Background(), time.Millisecond)
	out, err := (&flashrom{}).execReceive(ctx, "sleep", "60")
	timeConsumed := time.Since(startTime)
	require.Less(t, timeConsumed, time.Minute)
	require.Error(t, err)
	require.Nil(t, out)
}

func TestIntegrationExecReceiveHelloWorld(t *testing.T) {
	output, err := (&flashrom{}).execReceive(context.Background(), "curl", "file:///proc/cmdline", "-o", outputPathArgument)
	require.NoError(t, err)
	cmdLine, err := ioutil.ReadFile("/proc/cmdline")
	require.NoError(t, err)
	require.Equal(t, string(cmdLine), string(output))
}

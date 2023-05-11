//go:build linux && integration
// +build linux,integration

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
	"os"
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
	cmdLine, err := os.ReadFile("/proc/cmdline")
	require.NoError(t, err)
	require.Equal(t, string(cmdLine), string(output))
}

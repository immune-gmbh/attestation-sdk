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
	"fmt"
	"os/exec"

	"github.com/facebookincubator/go-belt/tool/logger"
)

type process interface {
	Output() ([]byte, error)
}

type processResult struct {
	Error  error
	Output []byte
}

type realProcess struct {
	cmd      *exec.Cmd
	doneChan chan processResult
}

func (f *flashrom) execCommand(ctx context.Context, cmd string, args ...string) process {
	if f.overrideExecCommandFunc != nil {
		return f.overrideExecCommandFunc(ctx, cmd, args...)
	}

	p := &realProcess{
		cmd:      exec.Command(cmd, args...),
		doneChan: make(chan processResult),
	}
	p.start(ctx)
	return p
}

func (p *realProcess) start(ctx context.Context) {
	cmdWaitChan := make(chan processResult)
	go func() {
		// Getting the output of real process execution.
		// Note: "p.cmd.Output()" != "p.Output()"
		output, outputErr := p.cmd.Output()
		cmdWaitChan <- processResult{
			Output: output,
			Error:  outputErr,
		}
		close(cmdWaitChan)
	}()

	go func() {
		select {
		case <-ctx.Done():
			err := fmt.Errorf("ctx cancelled: %w", ctx.Err())
			killErr := p.cmd.Process.Kill()
			logger.FromCtx(ctx).Debugf("%v; kill error: %v", err, killErr)
			p.doneChan <- processResult{
				Error: err,
			}
		case result := <-cmdWaitChan:
			logger.FromCtx(ctx).Debugf("wait-finish, result.Error == %v", result.Error)
			p.doneChan <- result
		}

		close(p.doneChan)
	}()
}

func (p *realProcess) Output() ([]byte, error) {
	result := <-p.doneChan
	return result.Output, result.Error
}

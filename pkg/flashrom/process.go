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

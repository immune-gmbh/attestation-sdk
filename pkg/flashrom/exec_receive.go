//go:build linux
// +build linux

package flashrom

import (
	"context"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/facebookincubator/go-belt/tool/logger"
)

const outputPathArgument = "${OUTPUT_PATH}"

func (f *flashrom) execReceive(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	// Unfortunately some tools like flashrom does not allow to suppress debugging
	// messages. Moreover it writes different debug messages to both pipes:
	// stdout and stderr. So there's no way to collect the firmware images
	// through standard io pipes.
	//
	// Therefore we create a new pipe without O_CLOEXEC and receive the
	// image through it.
	r, w, err := pipe()
	if err != nil {
		return nil, fmt.Errorf("unable to create a pipe: %w", err)
	}

	wFDPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), w.Fd())
	for idx, arg := range args {
		if arg == outputPathArgument {
			args[idx] = wFDPath
			break
		}
	}

	var outputErr error
	var output []byte

	outputEndChan := make(chan struct{})
	go func() {
		output, outputErr = io.ReadAll(r)
		_ = r.Close()
		close(outputEndChan)
	}()

	logger.FromCtx(ctx).Debugf("executing '%s' with args: %v", cmd, args)

	debugOutput, execErr := f.execCommand(ctx, cmd, args...).Output()

	_ = w.Close()
	if execErr != nil {
		return nil, fmt.Errorf("unable to exec %s %v: '%s': %w", cmd, args, debugOutput, execErr)
	}

	<-outputEndChan
	// TODO: handle outputErr
	logger.FromCtx(ctx).Debugf("output size is %d (outputErr: %v)", len(output), outputErr)
	return output, nil
}

func pipe() (*os.File, *os.File, error) {
	// unfortunately os.Pipe sets flag syscall.O_CLOEXEC, so we do our-own pipe()
	var pipeFDs [2]int
	err := syscall.Pipe(pipeFDs[:])
	if err != nil {
		return nil, nil, fmt.Errorf("unable to call syscall.Pipe(): %w", err)
	}

	r := os.NewFile(uintptr(pipeFDs[0]), "|0")
	w := os.NewFile(uintptr(pipeFDs[1]), "|1")
	return r, w, nil
}

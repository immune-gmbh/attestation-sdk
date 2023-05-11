package flashrom

import (
	"context"
)

type flashrom struct {
	Config config

	overrideExecCommandFunc func(ctx context.Context, name string, arg ...string) process
}

func newFlashrom(opts ...Option) *flashrom {
	return &flashrom{Config: getConfig(opts...)}
}

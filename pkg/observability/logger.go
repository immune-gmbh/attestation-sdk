package observability

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/adapter"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/facebookincubator/go-belt/tool/logger/types"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability/hooks/logentryfingerprint"
)

// NewLogger returns the default Logger for family of applications
// based on AttestationFailureAnalysisService.
func NewLogger(ctx context.Context, opts ...types.Option) logger.Logger {
	logrusEmitter := logrus.NewEmitter(logrus.DefaultLogrusLogger())

	var result logger.Logger
	result = adapter.LoggerFromEmitter(logrusEmitter)
	result = result.WithPreHooks(logentryfingerprint.PreHook{})
	result = result.WithLevel(logger.LevelTrace)
	return result
}

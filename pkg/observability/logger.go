package observability

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/facebookincubator/go-belt/tool/logger/types"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability/hooks/logentryfingerprint"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability/tool/logger/logrus/formatter"
)

// NewLogger returns the default Logger for family of applications
// based on AttestationFailureAnalysisService.
func NewLogger(ctx context.Context, opts ...types.Option) logger.Logger {
	l := logrus.DefaultLogrusLogger()
	l.Formatter = &formatter.CompactText{}

	result := logrus.New(l)
	result = result.WithPreHooks(logentryfingerprint.PreHook{})
	result = result.WithLevel(logger.LevelTrace)
	return result
}

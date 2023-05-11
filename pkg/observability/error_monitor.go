package observability

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	errmonlogger "github.com/facebookincubator/go-belt/tool/experimental/errmon/implementation/logger"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// NewErrorMonitor returns the default ErrorMonitor for family of applications
// based on AttestationFailureAnalysisService.
func NewErrorMonitor(ctx context.Context, l logger.Logger) errmon.ErrorMonitor {
	return errmonlogger.New(l)
}

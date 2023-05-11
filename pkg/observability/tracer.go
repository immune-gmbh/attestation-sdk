package observability

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
)

// NewTracer returns the default Tracer handler for family of applications
// based on AttestationFailureAnalysisService.
func NewTracer(ctx context.Context) tracer.Tracer {
	return tracer.Default()
}

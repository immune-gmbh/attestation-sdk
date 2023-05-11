package observability

import (
	"github.com/facebookincubator/go-belt/tool/experimental/metrics"
)

// NewMetrics returns the default Metrics handler for family of applications
// based on AttestationFailureAnalysisService.
func NewMetrics() metrics.Metrics {
	return metrics.Default()
}

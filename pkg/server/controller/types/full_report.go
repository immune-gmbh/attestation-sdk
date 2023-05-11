package types

import (
	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
)

// FullReport is the struct which contains the original data received from
// pcr0tool.
type FullReport struct {
	Report             diff.AnalysisReport
	DebugInfo          map[string]interface{}
	MeasurementsSHA1   pcr.Measurements
	MeasurementsSHA256 pcr.Measurements
}

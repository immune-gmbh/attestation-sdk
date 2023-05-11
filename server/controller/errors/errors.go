package errors

import (
	"fmt"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
)

func init() {
	analysis.RegisterType((*ErrInvalidInput)(nil))
}

// ErrInvalidInput means that input data is incorrect
type ErrInvalidInput struct {
	Err error
}

func (err ErrInvalidInput) Error() string {
	return fmt.Sprintf("invalid input: '%s'", err.Err)
}

func (err ErrInvalidInput) Unwrap() error {
	return err.Err
}

// ErrUnknownAnalyzer means there was a request with an analyzer input of unknown type.
// In other words the controller does not know about the requested Analyzer.
type ErrUnknownAnalyzer struct {
	AnalyzerInput afas.AnalyzerInput
}

func (err ErrUnknownAnalyzer) Error() string {
	return fmt.Sprintf("Analyzer '%s' is not supported", &err.AnalyzerInput)
}

package firmwarewand

import (
	"context"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
)

// Analyze sends a multi-analyzing request to AFAS
func (fwwand *FirmwareWand) Analyze(
	ctx context.Context,
	request *afas.AnalyzeRequest,
) (*afas.AnalyzeResult_, error) {
	return fwwand.firmwareAnalyzer.Analyze(request)
}

package firmwarewand

import (
	"context"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
)

// Analyze sends a multi-analyzing request to AFAS
func (fwwand *FirmwareWand) Analyze(
	ctx context.Context,
	request *afas.AnalyzeRequest,
) (*afas.AnalyzeResult_, error) {
	return fwwand.afasClient.Analyze(ctx, request)
}

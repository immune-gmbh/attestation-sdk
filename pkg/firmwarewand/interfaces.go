package firmwarewand

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
)

type firmwareAnalyzerInterface interface {
	afas.FirmwareAnalyzerClientInterface
}

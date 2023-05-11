package firmwarewand

import (
	"io"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
)

type afasClient interface {
	io.Closer
	afas.AttestationFailureAnalyzerService
}

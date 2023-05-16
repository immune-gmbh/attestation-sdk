package clienthelpers

import (
	"net/http"

	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/httputils/servermiddleware"
)

func HTTPHeaders(belt *belt.Belt, removeLogLevel logger.Level) http.Header {
	httpHeaders := http.Header{}

	if traceIDs := belt.TraceIDs(); traceIDs != nil {
		xTraceIDs := make([]string, 0, len(traceIDs))
		for _, traceID := range traceIDs {
			xTraceIDs = append(xTraceIDs, string(traceID))
		}
		httpHeaders[servermiddleware.HTTPHeaderTraceID] = xTraceIDs
	}

	if removeLogLevel != logger.LevelUndefined {
		httpHeaders[servermiddleware.HTTPHeaderNameLogLevel] = []string{removeLogLevel.String()}
	}

	return httpHeaders
}

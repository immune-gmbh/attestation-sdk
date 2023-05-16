package clientoptions

import (
	"context"
	"encoding/json"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/httputils/servermiddleware"
)

// Default returns thrift client options recommended to use with the
// go-belt-ed context. Currently it adds an HTTP-header to pass-through TraceIDs.
func Default(ctx context.Context) []thriftbase.Option {
	var result []thriftbase.Option

	result = append(result, thriftbase.WithContext(ctx))

	if logLevelRemote, ok := ctx.Value(ValueKeyLogLevelRemote).(logger.Level); ok {
		result = append(result, thriftbase.PersistentHeader(servermiddleware.HTTPHeaderNameLogLevel, logLevelRemote.String()))
	}

	if traceIDs := beltctx.Belt(ctx).TraceIDs(); traceIDs != nil {
		traceIDsJSON, err := json.Marshal(traceIDs)
		if err != nil {
			logger.FromCtx(ctx).Errorf("unable to marshal traceIDs %v: %v", traceIDs, err)
		} else {
			result = append(
				result,
				thriftbase.PersistentHeader(servermiddleware.HTTPHeaderTraceID, string(traceIDsJSON)),
			)
		}
	}

	return result
}

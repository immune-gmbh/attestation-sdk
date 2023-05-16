package servermiddleware

import (
	"net/http"

	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/logger"
)

const (
	// HTTPHeaderNameLogLevel is the name of a HTTP header used to
	// override the logging level on the server side.
	HTTPHeaderNameLogLevel = `X-Log-Level`

	// HTTPHeaderTraceID is the name of a HTTP header used to override
	// trace IDs.
	HTTPHeaderTraceID = `X-Trace-Id`
)

type valueKey string

const (
	// ValueKeyConnInfo is the context value key for thrift.ConnInfo
	ValueKeyConnInfo = valueKey("ConnInfo")

	// ValueKeyServiceTier is the context value key for tier used by client as
	// the destination to reach the service.
	ValueKeyServiceTier = valueKey("ServiceTier")
)

// SetupContext returns a server interceptor which sets up an extended context
// by cloning extensions (logger, metrics, ...) from "ctx" and setting logging
// level to "defaultLogLevel".
//
// The logging level could be overridden using HTTP-header "X-Log-Level"
// if overridableLogLevel is true.
func SetupContext(
	handler func(http.ResponseWriter, *http.Request),
	obsBelt *belt.Belt,
	overridableLogLevel bool,
	defaultLogLevel logger.Level,
) func(http.ResponseWriter, *http.Request) {
	obsBelt = obsBelt.WithField("apiInterface", "thrift")

	return func(response http.ResponseWriter, request *http.Request) {
		logLevel := defaultLogLevel

		ctx := request.Context()
		httpHeaders := request.Header

		var traceIDs belt.TraceIDs
		if xTraceIDs, ok := httpHeaders[HTTPHeaderTraceID]; ok {
			for _, xTraceID := range xTraceIDs {
				traceIDs = append(traceIDs, belt.TraceID(xTraceID))
			}
		} else {
			traceIDs = belt.TraceIDs{belt.RandomTraceID()}
		}

		var xLogLevelValue []string
		var logLevelErr error
		if overridableLogLevel {
			xLogLevelValue = httpHeaders[HTTPHeaderNameLogLevel]
			if len(xLogLevelValue) > 0 {
				var newLogLevel logger.Level
				logLevelErr = newLogLevel.Set(xLogLevelValue[0])
				if logLevelErr == nil && newLogLevel > logLevel {
					logLevel = newLogLevel
				}
			}
		}

		ctx = beltctx.WithBelt(ctx, obsBelt)
		ctx = logger.CtxWithLogger(ctx, logger.FromCtx(ctx).WithLevel(logLevel))
		ctx = beltctx.WithTraceID(ctx, traceIDs...)

		if logLevelErr != nil {
			logger.FromCtx(ctx).Warnf("unable to parse log level '%s': %v", xLogLevelValue, logLevelErr)
		}

		request = request.WithContext(ctx)
		handler(response, request)
	}
}

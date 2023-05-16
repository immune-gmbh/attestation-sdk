package servermiddleware

import (
	"net/http"

	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// AddDefaultMiddleware returns recommended thrift option for a server, it sets up a logger
// and an extended context, reads TraceID if was passed and recovers panics
// (and logs them through the initialized logger).
//
// For description of arguments see SetupContext.
func AddDefaultMiddleware(
	handler func(http.ResponseWriter, *http.Request),
	belt *belt.Belt,
	overridableLogLevel bool,
	defaultLogLevel logger.Level,
) func(http.ResponseWriter, *http.Request) {
	return SetupContext(RecoverPanic(LogClientHostname(LogRequests(handler))), belt, overridableLogLevel, defaultLogLevel)
}

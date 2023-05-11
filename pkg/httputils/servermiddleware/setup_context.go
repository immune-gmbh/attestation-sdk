// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

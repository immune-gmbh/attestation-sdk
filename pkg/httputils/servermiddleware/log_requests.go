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
	"time"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/pkg/field"
	"github.com/facebookincubator/go-belt/tool/experimental/metrics"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
)

type loggingResponseWriter struct {
	Backend http.ResponseWriter

	WriteLength int
	StatusCode  *int
}

var _ http.ResponseWriter = (*loggingResponseWriter)(nil)

func (w *loggingResponseWriter) Header() http.Header {
	return w.Backend.Header()
}
func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	w.WriteLength += len(b)
	return w.Backend.Write(b)
}
func (w *loggingResponseWriter) WriteHeader(statusCode int) {
	w.StatusCode = &statusCode
	w.Backend.WriteHeader(statusCode)
}

// LogRequests is a server interceptor to log and trace requests; and
// handle metrics about total about of requests and concurrent amount of requests.
//
// Should be executed only after SetupContext.
func LogRequests(
	handler func(http.ResponseWriter, *http.Request),
) func(http.ResponseWriter, *http.Request) {
	return func(_response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()

		metrics.FromCtx(ctx).Count("requests").Add(1)

		concurrentRequests := metrics.FromCtx(ctx).Gauge("concurrentRequests")
		concurrentRequests.Add(1)
		defer concurrentRequests.Add(-1)

		logger.FromCtx(ctx).WithFields(
			field.Prefix("http_header_", field.Map[[]string](request.Header)),
		).Debug("HTTP headers")

		startTime := time.Now()
		response := &loggingResponseWriter{Backend: _response}
		defer func() {
			total := time.Since(startTime)
			ctx := beltctx.WithFields(ctx, field.Map[any]{
				"totalNs":              total.Nanoseconds(),
				"response_header":      response.Header(),
				"response_status_code": response.StatusCode,
				"response_length":      response.WriteLength,
			})
			logger.FromCtx(ctx).Debug("request result")
		}()

		span, ctx := tracer.StartChildSpanFromCtx(ctx, "requestTotal")
		defer span.Finish()

		handler(response, request)
	}
}

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

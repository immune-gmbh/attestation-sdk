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

// LogRequests is a server interceptor to log and trace requests; and
// handle metrics about total about of requests and concurrent amount of requests.
//
// Should be executed only after SetupContext.
func LogRequests(
	handler func(http.ResponseWriter, *http.Request),
) func(http.ResponseWriter, *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		ctx := request.Context()

		metrics.FromCtx(ctx).Count("requests").Add(1)

		concurrentRequests := metrics.FromCtx(ctx).Gauge("concurrentRequests")
		concurrentRequests.Add(1)
		defer concurrentRequests.Add(-1)

		logger.FromCtx(ctx).WithFields(
			field.Prefix("http_header_", field.Map[[]string](request.Header)),
		).Debug("HTTP headers")

		startTime := time.Now()
		defer func() {
			total := time.Since(startTime)
			ctx := beltctx.WithFields(ctx, field.Map[any]{
				"totalNs":         total.Nanoseconds(),
				"response_header": response.Header(),
			})
			logger.FromCtx(ctx).Debug("request result")
		}()

		span, ctx := tracer.StartChildSpanFromCtx(ctx, "requestTotal")
		defer span.Finish()

		handler(response, request)
	}
}

package observability

import (
	"context"

	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/experimental/metrics"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// WithBelt returns a context derivative with the observability tool belt
// configured for purposes defined in virtual team "Fleet Integrity".
func WithBelt(
	ctx context.Context,
	logLevel logger.Level,
	traceIDPrefix string,
	setAsDefault bool,
) context.Context {
	ctx = logger.CtxWithLogger(ctx, NewLogger(ctx).WithLevel(logLevel))
	ctx = metrics.CtxWithMetrics(ctx, NewMetrics())
	ctx = errmon.CtxWithErrorMonitor(ctx, NewErrorMonitor(ctx, logger.FromCtx(ctx)))
	ctx = tracer.CtxWithTracer(ctx, NewTracer(ctx))
	ctx = beltctx.WithFields(ctx, DefaultFields())
	if traceIDPrefix != "" {
		ctx = beltctx.WithTraceID(ctx, belt.TraceID(traceIDPrefix+":")+belt.RandomTraceID())
	} else {
		ctx = beltctx.WithTraceID(ctx, belt.RandomTraceID())
	}
	if setAsDefault {
		setToolsAsDefault(beltctx.Belt(ctx))
	}
	return ctx
}

func setToolsAsDefault(b *belt.Belt) {
	belt.Default = func() *belt.Belt {
		return b
	}
	l := logger.FromBelt(b)
	logger.Default = func() logger.Logger {
		return l
	}
	m := metrics.FromBelt(b)
	metrics.Default = func() metrics.Metrics {
		return m
	}
	t := tracer.FromBelt(b)
	tracer.Default = func() tracer.Tracer {
		return t
	}
	e := errmon.FromBelt(b)
	errmon.Default = func(*belt.Belt) errmon.ErrorMonitor {
		return e
	}
}

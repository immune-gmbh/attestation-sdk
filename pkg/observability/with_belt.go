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

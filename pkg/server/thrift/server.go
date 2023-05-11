package thrift

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/facebookincubator/go-belt/tool/experimental/metrics"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/xaionaro-go/cpuload"

	"assistant/knowledge/fbutil/thwork"
	"libfb/go/stats/sysstat"

	fb303if "common/fb303/if/fb303"
	aclif "facebook/infrasec/authorization/acl"
	"libfb/go/aclchecker"
	"libfb/go/experimental/go-belt/thriftadapter/serverinterceptors"
	xmetrics "libfb/go/experimental/go-belt/tool/metrics"
	"libfb/go/go303"
	"libfb/go/stats/export"
	"libfb/go/stats/thriftstat"
	"libfb/go/thriftbase"
	"thrift/lib/go/thrift"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/server/controller"
)

type serviceInterface interface {
	Reset()
}

// Server is a firmware analysis server with Thrift interface.
type Server struct {
	HardConcurrentRequestsLimit uint
	MaxCPULoad                  float64
	ThworkServer                *thwork.Server

	service        serviceInterface
	cpuLoadMonitor *cpuload.Monitor
	context        context.Context
	serveCount     uint64
}

// Serve starts listening on bindAddr and serves it.
//
// This method could be executed only once.
func (srv *Server) Serve(
	ctx context.Context,
	bindAddr string,
) error {
	if atomic.AddUint64(&srv.serveCount, 1) > 1 {
		return fmt.Errorf("method Serve could be used only once")
	}
	defer srv.service.Reset()

	srv.context = ctx
	srv.cpuLoadMonitor = cpuload.NewMonitor(ctx, time.Second*10)

	{
		l := logger.FromCtx(ctx).WithField("module", "thwork")
		srv.ThworkServer.SetErrorLogFn(func(format string, args ...interface{}) {
			l.Errorf(format, args...)
		})
	}

	err := srv.ThworkServer.Listen(bindAddr)
	if err != nil {
		return fmt.Errorf("unable to listen '%s': %w", bindAddr, err)
	}

	return srv.ThworkServer.ServeContext(ctx)
}

func (srv *Server) isOverloaded() bool {
	log := logger.FromCtx(srv.context)
	concurrentRequests := srv.ThworkServer.ConcurrentRequestCount() + srv.ThworkServer.ScheduledCount()
	if srv.HardConcurrentRequestsLimit > 0 &&
		concurrentRequests > srv.HardConcurrentRequestsLimit {
		log.Errorf("too many requests")
		return true
	}

	if srv.MaxCPULoad > 0 && srv.cpuLoadMonitor.GetCPULoad() > srv.MaxCPULoad {
		log.Errorf("too high CPU load")
		return true
	}

	return false
}

// NewServer returns a Thrift server for a firmware analysis service.
func NewServer(
	ctx context.Context,
	numWorkers, hardConcurrentRequestsLimit uint,
	maxCPULoad float64,
	smcTier, hipsterACL string,
	ctrl *controller.Controller,
) (*Server, error) {

	// See: https://fb.workplace.com/groups/codegophers/permalink/2568081446573788/
	compositeProcessor := thriftbase.NewCompositeProcessorContext()
	stats := export.Get()
	if metrics, ok := metrics.FromCtx(ctx).(xmetrics.ToExportExporteder); ok {
		stats = metrics.ToExportExported()
	}
	err := sysstat.ExportTo(ctx, stats)
	if err != nil {
		return nil, fmt.Errorf("sysstat.ExportTo() error: %w", err)
	}

	go303Base := go303.NewBase(smcTier)
	go303Processor := fb303if.NewFacebookServiceProcessor(go303Base)
	compositeProcessor.IncludeContext(go303Processor)
	svc := newService(go303Base, ctrl, stats)
	proc := afas.NewFirmwareAnalyzerProcessor(svc)
	compositeProcessor.IncludeContext(proc)
	thriftstat.ExportTo(go303Processor, smcTier, stats)

	// add an ACL interceptor on thrift methods to filter who can do what.
	consumer := aclchecker.Identity{
		Type: aclif.TIER,
		Data: hipsterACL,
	}
	aclOpts := []aclchecker.Option{
		aclchecker.AllowAnon("DiffFirmware"),
		aclchecker.AllowAnon("SearchFirmware"),
		aclchecker.AllowAnon("SearchReport"),
		aclchecker.AllowAnon("ReportHostConfiguration"),
		aclchecker.AllowAnon("Analyze"),
		aclchecker.AllowAnon("CheckFirmwareVersion"),
	}

	thworkServer := thwork.NewWithoutProcs("privatecore.firmware-analyzer")
	thworkServer.AddProcessor(compositeProcessor, smcTier)
	thworkServer.SetNumWorkers(int(numWorkers))
	stats.Delegate(thworkServer.Exported())
	var serverInterceptors []thrift.Interceptor
	serverInterceptors = append(serverInterceptors, aclchecker.NewInterceptor(&consumer, aclOpts...))
	serverInterceptors = append(serverInterceptors, serverinterceptors.Default(ctx, true, logger.FromCtx(ctx).Level())...)
	thworkServer.SetInterceptor(thriftbase.ChainInterceptors(serverInterceptors...))

	srv := &Server{
		ThworkServer:                thworkServer,
		HardConcurrentRequestsLimit: hardConcurrentRequestsLimit,
		MaxCPULoad:                  maxCPULoad,
		service:                     svc,
	}
	thworkServer.SetLoadShedFn(func() bool { return srv.isOverloaded() })
	return srv, nil
}

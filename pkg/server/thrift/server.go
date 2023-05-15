package thrift

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/apache/thrift/lib/go/thrift"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller"
)

type serviceInterface interface {
	Reset()
}

// Server is a firmware analysis server with Thrift interface.
type Server struct {
	HardConcurrentRequestsLimit uint
	MaxCPULoad                  float64

	service    serviceInterface
	serveCount uint64
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
	return http.ListenAndServe(bindAddr, nil)
}

// NewServer returns a Thrift server for a firmware analysis service.
func NewServer(
	numWorkers, hardConcurrentRequestsLimit uint,
	maxCPULoad float64,
	ctrl *controller.Controller,
) (*Server, error) {
	protocolFactory := thrift.NewTJSONProtocolFactory()
	svc := newService(ctrl)
	processor := afas.NewAttestationFailureAnalyzerServiceProcessor(svc)
	http.HandleFunc("/", thrift.NewThriftHandlerFunc(processor, protocolFactory, protocolFactory))
	srv := &Server{
		HardConcurrentRequestsLimit: hardConcurrentRequestsLimit,
		MaxCPULoad:                  maxCPULoad,
		service:                     newService(ctrl),
	}
	return srv, nil
}

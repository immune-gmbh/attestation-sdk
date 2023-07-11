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
package thrift

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/pkg/httputils/servermiddleware"
	"github.com/immune-gmbh/attestation-sdk/pkg/server/controller"
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
	observability *belt.Belt,
	logLevel logger.Level,
) (*Server, error) {
	protocolFactory := thrift.NewTBinaryProtocolFactoryConf(nil)
	svc := newService(ctrl)
	processor := afas.NewAttestationFailureAnalyzerServiceProcessor(svc)
	handler := thrift.NewThriftHandlerFunc(processor, protocolFactory, protocolFactory)
	handler = servermiddleware.AddDefaultMiddleware(handler, observability, true, logLevel)
	http.HandleFunc("/", handler)
	srv := &Server{
		HardConcurrentRequestsLimit: hardConcurrentRequestsLimit,
		MaxCPULoad:                  maxCPULoad,
		service:                     newService(ctrl),
	}
	return srv, nil
}

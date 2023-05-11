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

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/hashicorp/go-multierror"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/httputils/clienthelpers"
)

const (
	// DefaultTimeout is the default value of the thrift client timeout.
	// It is so large because analyzing of a firmware image usually takes
	// few seconds, so we allow up-to 1 minute just in case.
	DefaultTimeout = time.Minute

	// DefaultProtocol is the default protocol used for Thrift
	DefaultProtocol = "binary"
)

const (
	miB = 1 << 20
)

var (
	// MaxFirmwareImageSize defines the maximum allowed size of a firmware image
	// to be sent.
	MaxFirmwareImageSize = uint(256 * miB)
)

// Backend is just a type-alias to the actual Thrift client, which then being wrapped
// with the fanciness of this package.
type Backend = afas.AttestationFailureAnalyzerServiceClient

// Client is just a client for the firmware analyzer service.
type Client struct {
	*Backend
	BackendTransport thrift.TTransport
}

// NewClient constructs a client for the firmware analyzer service.
func NewClient(ctx context.Context, opts ...Option) (*Client, error) {
	beltctx.WithField(ctx, "pkg", "afas_client")

	cfg := initConfig{
		Timeout:        DefaultTimeout,
		RemoteLogLevel: logger.LevelWarning,
		Protocol:       DefaultProtocol,
	}
	for _, opt := range opts {
		opt.apply(&cfg)
	}

	backendClient, transport, err := newBackend(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize a thrift client: %w", err)
	}

	return &Client{
		Backend:          backendClient,
		BackendTransport: transport,
	}, nil
}

func (c *Client) Close() error {
	return c.BackendTransport.Close()
}

func newBackend(
	ctx context.Context,
	cfg initConfig,
) (
	*afas.AttestationFailureAnalyzerServiceClient,
	thrift.TTransport,
	error,
) {
	if len(cfg.Endpoints) == 0 {
		return nil, nil, fmt.Errorf("no endpoints defined")
	}

	httpHeaders := clienthelpers.HTTPHeaders(beltctx.Belt(ctx), cfg.RemoteLogLevel)

	var errors error
	for _, endpoint := range cfg.Endpoints {
		backendClient, transport, err := newBackendUsingBackend(ctx, endpoint, cfg.Timeout, cfg.Protocol, httpHeaders)
		errmon.ObserveErrorCtx(ctx, err)
		if err != nil {
			multierror.Append(errors, fmt.Errorf("unable to initialize a thrift client using endpoint '%s': %w", endpoint, err))
		}
		if backendClient != nil {
			return backendClient, transport, nil
		}
	}
	return nil, nil, errors
}

func newBackendUsingBackend(
	ctx context.Context,
	endpoint string,
	timeout time.Duration,
	protocol string,
	httpHeaders http.Header,
) (
	*afas.AttestationFailureAnalyzerServiceClient,
	thrift.TTransport,
	error,
) {
	urlParsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse endpoint '%s': %w", endpoint, err)
	}

	transport, err := getThriftTransport(ctx, urlParsed, timeout, httpHeaders)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to initialize Thrift transport to '%s': %w", endpoint, err)
	}

	protoInput, protoOutput, err := getProtocols(ctx, transport, protocol)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to initialize Thrift protocol '%s': %w", protocol, err)
	}

	backendClient := afas.NewAttestationFailureAnalyzerServiceClient(newThriftStandardClientThreadSafe(protoInput, protoOutput))
	if err := transport.Open(); err != nil {
		return nil, nil, fmt.Errorf("unable to open a socket to '%s': %w", urlParsed.Host, err)
	}

	return backendClient, transport, nil
}

func getThriftTransport(
	ctx context.Context,
	urlParsed *url.URL,
	timeout time.Duration,
	httpHeaders http.Header,
) (
	thrift.TTransport,
	error,
) {
	switch strings.ToLower(urlParsed.Scheme) {
	case "http", "https":
		return getThriftTransportHTTP(ctx, urlParsed, httpHeaders, timeout)
	case "tcp":
		return getThriftTransportTCP(ctx, urlParsed, false, timeout)
	case "tcp_framed":
		return getThriftTransportTCP(ctx, urlParsed, true, timeout)
	}

	return nil, fmt.Errorf("unknown network scheme: '%s'", urlParsed.Scheme)
}

func getThriftTransportHTTP(
	ctx context.Context,
	urlParsed *url.URL,
	httpHeaders http.Header,
	_ time.Duration,
) (
	thrift.TTransport,
	error,
) {
	transport, err := thrift.NewTHttpClient(urlParsed.String())
	if err != nil {
		return nil, fmt.Errorf("unable to initialize HTTP Thrift client: %w", err)
	}

	if len(httpHeaders) > 0 {
		httpTransport := transport.(*thrift.THttpClient)
		for key, values := range httpHeaders {
			for _, value := range values {
				httpTransport.SetHeader(key, value)
			}
		}
	}

	return transport, nil
}

func getThriftTransportTCP(
	ctx context.Context,
	urlParsed *url.URL,
	isFramed bool,
	timeout time.Duration,
) (
	thrift.TTransport,
	error,
) {
	var transport thrift.TTransport
	transport = thrift.NewTSocketConf(urlParsed.Host, &thrift.TConfiguration{
		ConnectTimeout: timeout,
		SocketTimeout:  timeout,
	})
	if isFramed {
		transport = thrift.NewTFramedTransportConf(transport, nil)
	}

	return transport, nil
}

func getProtocols(
	ctx context.Context,
	transport thrift.TTransport,
	protocol string,
) (
	thrift.TProtocol,
	thrift.TProtocol,
	error,
) {
	var protocolFactory thrift.TProtocolFactory
	switch protocol {
	case "compact":
		protocolFactory = thrift.NewTCompactProtocolFactoryConf(nil)
	case "simplejson":
		protocolFactory = thrift.NewTSimpleJSONProtocolFactoryConf(nil)
	case "json":
		protocolFactory = thrift.NewTJSONProtocolFactory()
	case "binary":
		protocolFactory = thrift.NewTBinaryProtocolFactoryConf(nil)
	default:
		return nil, nil, fmt.Errorf("unknown protocol: '%s'", protocol)
	}

	return protocolFactory.GetProtocol(transport), protocolFactory.GetProtocol(transport), nil
}

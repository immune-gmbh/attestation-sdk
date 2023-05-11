package client

import (
	"net/http"
	"time"

	"github.com/facebookincubator/go-belt/tool/logger"
)

type initConfig struct {
	Timeout          time.Duration
	Endpoints        []string
	Protocol         string
	RemoteLogLevel   logger.Level
	LogLocalHostname string
	HTTPHeaders      http.Header
}

// Option is an abstract option for NewClient.
type Option interface {
	apply(*initConfig)
}

// OptionTimeout is an option to set the timeout for the thrift client.
type OptionTimeout time.Duration

func (opt OptionTimeout) apply(config *initConfig) {
	config.Timeout = time.Duration(opt)
}

// OptionEndpoints is an option to set an address to connect to instead of
// SMC tier through SR.
type OptionEndpoints []string

func (opt OptionEndpoints) apply(config *initConfig) {
	config.Endpoints = opt
}

// OptionRemoteLogLevel is an option to override logging level on the server.
type OptionRemoteLogLevel logger.Level

func (opt OptionRemoteLogLevel) apply(config *initConfig) {
	config.RemoteLogLevel = logger.Level(opt)
}

// OptionLogLocalHostname is an option to sent local hostname to the server, to
// get it logged on the serve side
type OptionLogLocalHostname string

func (opt OptionLogLocalHostname) apply(config *initConfig) {
	config.LogLocalHostname = string(opt)
}

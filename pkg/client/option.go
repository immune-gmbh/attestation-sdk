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
	"time"

	"github.com/facebookincubator/go-belt/tool/logger"
)

type initConfig struct {
	Timeout          time.Duration
	Endpoints        []string
	Protocol         string
	RemoteLogLevel   logger.Level
	LogLocalHostname string
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

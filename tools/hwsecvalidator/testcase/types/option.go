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
package types

import (
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"
)

// Config is the settings used to adjust the validation process.
type Config struct {
	FlashromOptions              []flashrom.Option
	UseFirmwareExpectedAsCurrent bool
	UsePCR0ExpectedAsCurrent     bool
	ForceStatusRegisters         registers.Registers
	ForceEventLog                []*tpmeventlog.Event
	HostNotBooted                bool
	ForceSELEvents               []SEL
}

// Option is a single setting, see Config.
type Option interface {
	Apply(cfg *Config)
}

// OptionFlashrom sets options to "flashrom".
type OptionFlashrom []flashrom.Option

// Apply implements Option
func (opt OptionFlashrom) Apply(cfg *Config) {
	cfg.FlashromOptions = opt
}

// OptionUseFirmwareExpectedAsCurrent avoids dumping real current firmware
// and assumes it is the same as expected, instead.
type OptionUseFirmwareExpectedAsCurrent bool

// Apply implements Option
func (opt OptionUseFirmwareExpectedAsCurrent) Apply(cfg *Config) {
	cfg.UseFirmwareExpectedAsCurrent = bool(opt)
}

// OptionUsePCR0ExpectedAsCurrent avoids dumping real current PCR0 values
// and assumes they are the same as expected, instead.
type OptionUsePCR0ExpectedAsCurrent bool

// Apply implements Option
func (opt OptionUsePCR0ExpectedAsCurrent) Apply(cfg *Config) {
	cfg.UsePCR0ExpectedAsCurrent = bool(opt)
}

// OptionForceStatusRegisters avoids dumping real status registers and
// uses the defined ones, instead.
type OptionForceStatusRegisters registers.Registers

// Apply implements Option
func (opt OptionForceStatusRegisters) Apply(cfg *Config) {
	cfg.ForceStatusRegisters = registers.Registers(opt)
}

// OptionForceEventLog avoids dumping real TPM EventLog and
// uses the defined one, instead.
type OptionForceEventLog []*tpmeventlog.Event

// Apply implements Option
func (opt OptionForceEventLog) Apply(cfg *Config) {
	cfg.ForceEventLog = opt
}

// OptionHostNotBooted tells the underlying test that the host was not booted
type OptionHostNotBooted struct{}

// Apply implements Option
func (opt OptionHostNotBooted) Apply(cfg *Config) {
	cfg.HostNotBooted = true
}

// OptionForceSELEvents provides SEL events to the test
type OptionForceSELEvents []SEL

// Apply implements Option
func (opt OptionForceSELEvents) Apply(cfg *Config) {
	cfg.ForceSELEvents = opt
}

// Options is a set of Option-s.
type Options []Option

// Config converts Options to Config.
func (opts Options) Config() Config {
	cfg := Config{}
	for _, opt := range opts {
		opt.Apply(&cfg)
	}
	return cfg
}

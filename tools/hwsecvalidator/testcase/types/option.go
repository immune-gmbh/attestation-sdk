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

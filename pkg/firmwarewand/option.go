package firmwarewand

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"

	"github.com/facebookincubator/go-belt/tool/logger"
)

type config struct {
	FirmwareAnalyzerSMCTier   string
	firmwareAnalyzerEndpoints []string
	FirmwareAnalyzerLogLevel  logger.Level
	FlashromOptions           []flashrom.Option
}

type Option interface {
	apply(*config)
}

type OptionFirmwareAnalyzerSMCTier string

func (opt OptionFirmwareAnalyzerSMCTier) apply(cfg *config) {
	cfg.FirmwareAnalyzerSMCTier = string(opt)
}

// OptionFirmwareAnalyzerEndpoints specifies an exact endpoint to connect to
// if present, has priority over SMC tier
type OptionFirmwareAnalyzerEndpoints []string

func (opt OptionFirmwareAnalyzerEndpoints) apply(cfg *config) {
	cfg.firmwareAnalyzerEndpoints = opt
}

type OptionFlashromOptions []flashrom.Option

func (opt OptionFlashromOptions) apply(cfg *config) {
	cfg.FlashromOptions = opt
}

type OptionRemoteLogLevel logger.Level

func (opt OptionRemoteLogLevel) apply(cfg *config) {
	cfg.FirmwareAnalyzerLogLevel = logger.Level(opt)
}

func getConfig(opts ...Option) config {
	cfg := config{
		FirmwareAnalyzerLogLevel: logger.LevelWarning,
	}
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	return cfg
}

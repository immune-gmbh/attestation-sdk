package firmwarewand

import (
	"context"
	"os"

	"libfb/go/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"

	"github.com/facebookincubator/go-belt/beltctx"
)

// FirmwareWand is a collection of client-side analysis tooling for a BIOS firmware
type FirmwareWand struct {
	context          context.Context
	firmwareAnalyzer firmwareAnalyzerInterface
	flashromOptions  []flashrom.Option
}

// New creates a new instance of a FirmwareWand
func New(ctx context.Context, opts ...Option) (*FirmwareWand, error) {
	ctx = beltctx.WithField(ctx, "pkg", "firmwarewand")
	cfg := getConfig(opts...)

	var firmwareAnalyzerOptions []afas.Option
	firmwareAnalyzerOptions = append(firmwareAnalyzerOptions,
		afas.OptionRemoteLogLevel(cfg.FirmwareAnalyzerLogLevel),
	)
	if hostname, err := os.Hostname(); err == nil {
		firmwareAnalyzerOptions = append(firmwareAnalyzerOptions, afas.OptionLogLocalHostname(hostname))
	}
	if cfg.firmwareAnalyzerEndpoints != nil {
		firmwareAnalyzerOptions = append(firmwareAnalyzerOptions, afas.OptionEndpoints(cfg.firmwareAnalyzerEndpoints))
	}
	if cfg.FirmwareAnalyzerSMCTier != "" {
		firmwareAnalyzerOptions = append(firmwareAnalyzerOptions, afas.OptionSMCTier(cfg.FirmwareAnalyzerSMCTier))
	}

	fwAnalyzer, err := afas.NewClient(ctx, firmwareAnalyzerOptions...)
	if err != nil {
		return nil, ErrInitFirmwareAnalyzer{Err: err}
	}

	return &FirmwareWand{
		context:          ctx,
		firmwareAnalyzer: fwAnalyzer,
		flashromOptions:  cfg.FlashromOptions,
	}, nil
}

func (fwwand *FirmwareWand) Close() error {
	return fwwand.firmwareAnalyzer.Close()
}

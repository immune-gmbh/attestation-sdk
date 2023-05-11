package firmwarewand

import (
	"context"
	"os"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/client"
	afas_client "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/client"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"

	"github.com/facebookincubator/go-belt/beltctx"
)

// FirmwareWand is a collection of client-side analysis tooling for a BIOS firmware
type FirmwareWand struct {
	afasClient      afasClient
	flashromOptions []flashrom.Option
}

// New creates a new instance of a FirmwareWand
func New(ctx context.Context, opts ...Option) (*FirmwareWand, error) {
	ctx = beltctx.WithField(ctx, "pkg", "firmwarewand")
	cfg := getConfig(opts...)

	var firmwareAnalyzerOptions []afas_client.Option
	firmwareAnalyzerOptions = append(firmwareAnalyzerOptions,
		afas_client.OptionRemoteLogLevel(cfg.AFASLogLevel),
	)
	if hostname, err := os.Hostname(); err == nil {
		firmwareAnalyzerOptions = append(firmwareAnalyzerOptions, afas_client.OptionLogLocalHostname(hostname))
	}
	if cfg.afasEndpoints != nil {
		firmwareAnalyzerOptions = append(firmwareAnalyzerOptions, afas_client.OptionEndpoints(cfg.afasEndpoints))
	}

	afasClient, err := client.NewClient(ctx, firmwareAnalyzerOptions...)
	if err != nil {
		return nil, ErrInitFirmwareAnalyzer{Err: err}
	}

	return &FirmwareWand{
		afasClient:      afasClient,
		flashromOptions: cfg.FlashromOptions,
	}, nil
}

func (fwwand *FirmwareWand) Close() error {
	return fwwand.afasClient.Close()
}

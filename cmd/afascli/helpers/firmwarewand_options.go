package helpers

import (
	"fmt"
	"strings"

	afasclient "github.com/immune-gmbh/AttestationFailureAnalysisService/client"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
	"syseng/yard/attestation/lib/yard"
)

// FirmwarewandOptions returns firmwarewand.Option-s should be use to initialize
// firmwarewand in afascli/cmd/ verbs.
func FirmwarewandOptions(addrs string) []firmwarewand.Option {
	if addrs == "" {
		opts := []firmwarewand.Option{firmwarewand.OptionFirmwareAnalyzerSMCTier(afasclient.DefaultSMCTier)}

		cfg, err := yard.NewConfig()
		if err != nil {
			return opts
		}

		opts = append(opts, firmwarewand.OptionFirmwareAnalyzerEndpoints(cfg.ClosestFirmwareAnalyzerEndpointsV6))
		return opts
	}

	var smcTier string
	var endpoints []string
	for _, addr := range strings.Split(addrs, ",") {
		if addr != "" {
			if strings.Contains(addr, ":") {
				endpoints = append(endpoints, addr)
				continue
			}
			if smcTier != "" {
				panic(fmt.Sprintf("SMC tier is defined multiple times: %s and %s", smcTier, addr))
			}
			smcTier = addr
		}
	}

	var opts []firmwarewand.Option
	if smcTier != "" {
		opts = append(opts, firmwarewand.OptionFirmwareAnalyzerSMCTier(smcTier))
	}
	if len(endpoints) != 0 {
		opts = append(opts, firmwarewand.OptionFirmwareAnalyzerEndpoints(endpoints))
	}

	return opts
}

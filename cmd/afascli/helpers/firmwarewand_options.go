package helpers

import (
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
)

// FirmwarewandOptions returns firmwarewand.Option-s should be use to initialize
// firmwarewand in afascli/cmd/ verbs.
func FirmwarewandOptions(addrs string) []firmwarewand.Option {
	var endpoints []string
	for _, addr := range strings.Split(addrs, ",") {
		if addr == "" {
			continue
		}
		endpoints = append(endpoints, addr)
	}

	var opts []firmwarewand.Option
	if len(endpoints) != 0 {
		opts = append(opts, firmwarewand.OptionFirmwareAnalyzerEndpoints(endpoints))
	}

	return opts
}

package commands

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
)

type Config struct {
	IsQuiet             bool
	FirmwareWandOptions []firmwarewand.Option
}

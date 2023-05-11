package commands

import (
	"context"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
)

type Config struct {
	IsQuiet             bool
	Context             context.Context
	FirmwareWandOptions []firmwarewand.Option
}

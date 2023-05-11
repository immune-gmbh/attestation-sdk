package pcr0sum

import (
	"context"
	"log"
	"os"

	"github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/sum"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	sum.Command
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, cfg commands.Config, args []string) error {
	// TODO: make pcr0tool compatible with "commands.Config" and use it directly
	log.SetOutput(os.Stdout)
	cmd.Command.Execute(cfg.Context, args)
	return nil
}

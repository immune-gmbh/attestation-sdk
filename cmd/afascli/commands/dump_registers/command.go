package dump_registers

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	xregisters "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/registers"

	css_helpers "github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands/dumpregisters/helpers"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	firmwareAnalysisAddress *string
	firmwareVersion         *string
	firmwareDate            *string
	printReport             *bool
	tags                    *string
	humanReadable           *bool
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "dump register values"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.humanReadable = flag.Bool("hr", false, "dump registers in human readable format")
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, cfg commands.Config, args []string) error {
	if len(args) > 0 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many parameters")}
	}

	allRegisters, err := xregisters.LocalRegisters()
	if allRegisters == nil && err != nil {
		return fmt.Errorf("unable to fetch local registers: %w", err)
	}

	if *cmd.humanReadable {
		css_helpers.PrintRegisters(allRegisters)
	} else {
		b, err := json.Marshal(allRegisters)
		if err != nil {
			return fmt.Errorf("unable to serialize registers: %w", err)
		}
		fmt.Printf("%s\n", b)
	}
	return nil
}

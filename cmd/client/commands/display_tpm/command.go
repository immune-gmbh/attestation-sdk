package display_tpm

import (
	"flag"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
)

// Command is the implementation of `commands.Command`.
type Command struct {
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "display information about local TPM"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(cfg commands.Config, args []string) error {
	localTPM, err := tpmdetection.Local()
	if err != nil {
		fmt.Printf("Failed to detect local TPM, err: %v", err)
		return err
	}
	fmt.Printf("Local TPM: %s\n", localTPM.String())
	return nil
}

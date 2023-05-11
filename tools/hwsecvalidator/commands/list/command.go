package list

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/registry"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
)

// Command is the implementation of `commands.Command`.
type Command struct {
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<path to the image>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "print available test cases"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, cfg commands.Config, args []string) error {
	if len(args) < 1 {
		return commands.ErrArgs{Err: fmt.Errorf("error: no path to the firmare was specified")}
	}
	if len(args) > 1 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many parameters")}
	}
	imagePath := args[0]

	image, err := ioutil.ReadFile(imagePath)
	if err != nil {
		return fmt.Errorf("failed to read firmware image file: %w", err)
	}

	fwInfo, err := types.NewFirmwareInfoProvider(image)
	if err != nil {
		return fmt.Errorf("failed to parse firmware: %w", err)
	}

	suitableTestCases := registry.AllForFirmware(fwInfo)
	fmt.Println(strings.Join(suitableTestCases.Names(), ","))
	return nil
}

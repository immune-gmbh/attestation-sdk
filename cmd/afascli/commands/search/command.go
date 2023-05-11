package search

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"

	afasclient "github.com/immune-gmbh/AttestationFailureAnalysisService/client"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	verbhelpers "github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/afascli/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	firmwareAnalysisAddress *string
	imageID                 *string
	version                 *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "search for firmwares"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	// for "firmwareAnalysisAddress" see the comment in ../verify/command.go
	cmd.firmwareAnalysisAddress = flag.String("firmware-analysis-addr", "", "SMC tier of the firmware analysis service (default is '"+afasclient.DefaultSMCTier+"' with fallback on endpoints from '/tmp/yard_config.json')")

	cmd.imageID = flag.String("image-id", "", "ImageID to filter the reports by")
	cmd.version = flag.String("version", "", "firmware version")
}

func (cmd Command) firmwarewandOptions() []firmwarewand.Option {
	return verbhelpers.FirmwarewandOptions(*cmd.firmwareAnalysisAddress)
}

func (cmd Command) flagImageID() ([]byte, error) {
	if *cmd.imageID == "" {
		return nil, nil
	}

	return hex.DecodeString(*cmd.imageID)
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(cfg commands.Config, args []string) error {
	if len(args) != 0 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many arguments")}
	}

	fwWand, err := firmwarewand.New(cfg.Context, append(cfg.FirmwareWandOptions, cmd.firmwarewandOptions()...)...)
	if err != nil {
		return fmt.Errorf("unable to initialize a firmwarewand: %w", err)
	}

	searchFilters := afas.SearchFirmwareFilters{}
	if *cmd.version != "" {
		searchFilters.Version = cmd.version
	}
	if *cmd.imageID != "" {
		searchFilters.ImageID, err = cmd.flagImageID()
		if err != nil {
			return commands.ErrArgs{Err: fmt.Errorf("invalid image ID: %w", err)}
		}
	}

	entries, err := fwWand.Search(searchFilters, false)
	if err != nil {
		return fmt.Errorf("unable to perform a search: %w", err)
	}

	b, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("unable to serialize the firmware metadata: %w", err)
	}
	fmt.Printf("%s\n", b)

	return nil
}

package fetch

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/facebookincubator/go-belt/tool/logger"

	verbhelpers "github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/afascli/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	afasclient "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/client"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	firmwareAnalysisAddress *string
	outputFlag              *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<image ID>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "download a firmware image"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	// for "firmwareAnalysisAddress" see the comment in ../verify/command.go
	cmd.firmwareAnalysisAddress = flag.String("firmware-analysis-addr", "", "SMC tier of the firmware analysis service (default is '"+afasclient.DefaultSMCTier+"' with fallback on endpoints from '/tmp/yard_config.json')")

	cmd.outputFlag = flag.String("output", "", "the path to save the image by; if empty then the image will be printed to stdout")
}

func (cmd Command) firmwarewandOptions() []firmwarewand.Option {
	return verbhelpers.FirmwarewandOptions(*cmd.firmwareAnalysisAddress)
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, cfg commands.Config, args []string) error {
	if len(args) < 1 {
		return commands.ErrArgs{Err: fmt.Errorf("error: no image ID is specified")}
	}
	if len(args) > 1 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many parameters")}
	}
	imageIDStr := args[0]

	var imageID []byte
	var err error
	switch {
	case strings.HasPrefix(imageIDStr, "hex:"):
		imageID, err = hex.DecodeString(imageIDStr[4:])
	case strings.HasPrefix(imageIDStr, "base64:"):
		imageID, err = base64.StdEncoding.DecodeString(imageIDStr[7:])
	default:
		return commands.ErrArgs{Err: fmt.Errorf("image ID is expected in format 'hex:some_hex_encoded_string_here' or 'base64:some_base64_string_encoded_string_here'")}
	}
	if err != nil {
		return commands.ErrArgs{Err: fmt.Errorf("unable to parse image ID: %w", err)}
	}

	fwWand, err := firmwarewand.New(cfg.Context, append(cfg.FirmwareWandOptions, cmd.firmwarewandOptions()...)...)
	if err != nil {
		return fmt.Errorf("unable to initialize a firmwarewand: %w", err)
	}

	entries, err := fwWand.Search(
		cfg.Context,
		afas.SearchFirmwareFilters{ImageID: imageID},
		true,
	)
	if err != nil {
		return fmt.Errorf("unable to perform a search: %w", err)
	}

	if len(entries.Found) != 1 {
		return fmt.Errorf("expected one entry, but received %d", len(entries.Found))
	}
	image := entries.Found[0].Data

	var out io.Writer
	if *cmd.outputFlag != "" {
		f, err := os.Create(*cmd.outputFlag)
		if err != nil {
			return fmt.Errorf("unable to create/truncate file '%s': %w", *cmd.outputFlag, err)
		}
		defer func() {
			err := f.Close()
			if err != nil {
				logger.FromCtx(cfg.Context).Errorf("unable to close file '%s': %v", *cmd.outputFlag, err)
			}
		}()
		out = f
	} else {
		out = os.Stdout
	}

	_, err = out.Write(image)
	if err != nil {
		return fmt.Errorf("unable to output the image: %w", err)
	}

	return nil
}

// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

	verbhelpers "github.com/immune-gmbh/attestation-sdk/cmd/afascli/helpers"
	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/pkg/commands"
	"github.com/immune-gmbh/attestation-sdk/pkg/firmwarewand"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	afasEndpoint *string
	outputFlag   *string
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
	cmd.afasEndpoint = flag.String("afas-endpoint", "http://localhost:17545", "")
	cmd.outputFlag = flag.String("output", "", "the path to save the image by; if empty then the image will be printed to stdout")
}

func (cmd Command) firmwarewandOptions() []firmwarewand.Option {
	return verbhelpers.FirmwarewandOptions(*cmd.afasEndpoint)
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

	fwWand, err := firmwarewand.New(ctx, append(cfg.FirmwareWandOptions, cmd.firmwarewandOptions()...)...)
	if err != nil {
		return fmt.Errorf("unable to initialize a firmwarewand: %w", err)
	}

	entries, err := fwWand.Search(
		ctx,
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
				logger.FromCtx(ctx).Errorf("unable to close file '%s': %v", *cmd.outputFlag, err)
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

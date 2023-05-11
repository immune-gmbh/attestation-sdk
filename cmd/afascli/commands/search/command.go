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

package search

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"

	verbhelpers "github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/afascli/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	afasEndpoint *string
	imageID      *string
	version      *string
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
	cmd.afasEndpoint = flag.String("afas-endpoint", "http://localhost:17545", "")
	cmd.imageID = flag.String("image-id", "", "ImageID to filter the reports by")
	cmd.version = flag.String("version", "", "firmware version")
}

func (cmd Command) firmwarewandOptions() []firmwarewand.Option {
	return verbhelpers.FirmwarewandOptions(*cmd.afasEndpoint)
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
func (cmd Command) Execute(ctx context.Context, cfg commands.Config, args []string) error {
	if len(args) != 0 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many arguments")}
	}

	fwWand, err := firmwarewand.New(ctx, append(cfg.FirmwareWandOptions, cmd.firmwarewandOptions()...)...)
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

	entries, err := fwWand.Search(ctx, searchFilters, false)
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

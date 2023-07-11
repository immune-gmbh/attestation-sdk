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

package display_info

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/immune-gmbh/attestation-sdk/pkg/commands"
	"github.com/immune-gmbh/attestation-sdk/pkg/dmidecode"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	firmwareAnalysisAddress *string
	firmwareVersion         *string
	firmwareDate            *string
	printReport             *bool
	tags                    *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<path to the image>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "display information about firmware image"
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

	imageBytes, err := os.ReadFile(imagePath)
	if err != nil {
		return fmt.Errorf("unable to read image '%s': %w", imagePath, err)
	}

	dmiTable, err := dmidecode.DMITableFromFirmwareImage(imageBytes)
	if err != nil {
		return fmt.Errorf("unable to parse the image info: '%w'", err)
	}

	b, err := json.Marshal(dmiTable.BIOSInfo())
	if err != nil {
		return fmt.Errorf("unable to serialize BIOSInfo: %w", err)
	}
	fmt.Printf("%s\n", b)

	return nil
}

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

package dump

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/immune-gmbh/attestation-sdk/pkg/commands"
	"github.com/immune-gmbh/attestation-sdk/pkg/flashrom"

	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	DumpMethod   *string
	PathFlashrom *string
	PathAfulnx64 *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<output-file>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "dump firmware image from local machine"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.DumpMethod = flag.String("dump-method", "auto", "possible values: flashrom, afulnx64, devmem, mtd, auto")
	cmd.PathFlashrom = flag.String("path-flashrom", "", "path to flashrom")
	cmd.PathAfulnx64 = flag.String("path-afulnx64", "", "path to afulnx64")
}

// FlashromOptions returns options to be used in package "flashrom".
func (cmd Command) FlashromOptions() []flashrom.Option {
	var result []flashrom.Option

	var dumpMethod flashrom.DumpMethod
	switch strings.ToLower(*cmd.DumpMethod) {
	case "auto":
		dumpMethod = flashrom.DumpMethodAuto
	case "flashrom":
		dumpMethod = flashrom.DumpMethodFlashrom
	case "afulnx64":
		dumpMethod = flashrom.DumpMethodAfulnx64
	case "devmem":
		dumpMethod = flashrom.DumpMethodDevMem
	case "mtd":
		dumpMethod = flashrom.DumpMethodMTD
	}
	result = append(result, flashrom.OptionDumpMethod(dumpMethod))

	if *cmd.PathFlashrom != "" {
		result = append(result, flashrom.OptionFlashromPath(*cmd.PathFlashrom))
	}
	if *cmd.PathAfulnx64 != "" {
		result = append(result, flashrom.OptionAfulnx64Path(*cmd.PathAfulnx64))
	}

	return result
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
	outputPath := args[0]

	imageBytes, err := flashrom.Dump(ctx, cmd.FlashromOptions()...)
	if err != nil {
		return fmt.Errorf("unable to dump a firmware image: %w", err)
	}

	span, _ := tracer.StartChildSpanFromCtx(ctx, "writeFile")
	defer span.Finish()
	err = os.WriteFile(outputPath, imageBytes, 0440)
	if err != nil {
		return fmt.Errorf("unable to save the firmware image: %w", err)
	}

	return nil
}

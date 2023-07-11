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
package setup

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/immune-gmbh/attestation-sdk/pkg/commands"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/registry"
)

// Command is the implementation of `commands.Command`.
type Command struct {
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<test case> <original firmware> <modified firmware>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "modifies a firmware image for a specific test case"
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
	if len(args) < 3 {
		return commands.ErrArgs{Err: fmt.Errorf("error: no path to the firmare was specified")}
	}
	if len(args) > 3 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many parameters")}
	}
	testCaseName := args[0]
	origImagePath := args[1]
	dstImagePath := args[2]

	testCases := registry.All()
	testCase := testCases.Find(testCaseName)
	if testCase == nil {
		return commands.ErrArgs{Err: fmt.Errorf("unknown test case '%s', available values are: %s",
			testCaseName,
			strings.Join(testCases.Names(), ","),
		)}
	}

	image, err := os.ReadFile(origImagePath)
	if err != nil {
		return fmt.Errorf("unable to read to original image '%s': %w", origImagePath, err)
	}

	if err := testCase.Setup(ctx, image); err != nil {
		return fmt.Errorf("unable to setup the test case '%s': %w", testCaseName, err)
	}

	if err := os.WriteFile(dstImagePath, image, 0640); err != nil {
		return fmt.Errorf("unable to save the modified firmware image to '%s': %w", dstImagePath, err)
	}

	fwtestToolAbsPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		fwtestToolAbsPath = os.Args[0]
	}

	origImageAbsPath, err := filepath.Abs(dstImagePath)
	if err != nil {
		origImageAbsPath = origImagePath
	}

	fmt.Printf(`The modified image is written to '%s'.
It is required to flash the firmware to the system and reboot it.
After that execute "'%s' validate '%s'" to get the test result.
`, dstImagePath, fwtestToolAbsPath, origImageAbsPath)

	return nil
}

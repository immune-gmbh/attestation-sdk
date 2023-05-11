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

package txt_status

import (
	"context"
	"flag"
	"fmt"
	"reflect"

	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/txt_errors"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

// Command is the implementation of `commands.Command`.
type Command struct{}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "returns a diagnosis of the TXT state"
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
	if len(args) > 0 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many parameters")}
	}

	txtAPI := hwapi.GetAPI()

	txtConfig, err := registers.FetchTXTConfigSpaceSafe(txtAPI)
	if err != nil {
		return fmt.Errorf("unable to fetch TXT config space: %w", err)
	}
	txtRegisters, _ := registers.ReadTXTRegisters(txtConfig)

	acmStatusIface := txtRegisters.Find(registers.ACMStatusRegisterID)
	if acmStatusIface == nil {
		return fmt.Errorf("unable to find ACM_STATUS register")
	}
	acmStatus := acmStatusIface.(registers.ACMStatus)

	return newResult(acmStatus.ClassCode(), acmStatus.MajorErrorCode(), acmStatus.MinorErrorCode()).Error()
}

type Result struct {
	Class uint8
	Major uint8
	Minor uint16
}

func newResult(class, major uint8, minor uint16) Result {
	return Result{
		Class: class,
		Major: major,
		Minor: minor,
	}
}

func (r Result) Error() error {
	if r.Class == 0 && r.Major == 0 && r.Minor == 0 {
		return nil
	}

	return ErrorResult{Result: r}
}

var _ commands.ExitCoder = ErrorResult{}

type ErrorResult struct {
	Result
}

func (r ErrorResult) Error() string {
	return fmt.Sprintf("%02X%02X%04X %s", r.Class, r.Major, r.Minor, txtErrorDescription(r.error()))
}

func (r ErrorResult) error() error {
	switch r.Class {
	case 0x11:
		switch r.Major {
		case 0x05:
			switch r.Minor {
			case 0x1C:
				return txt_errors.NewErrBPMRevoked()
			}
			return txt_errors.NewErrBPM()
		}
		return txt_errors.NewErrBPTIntegrity()
	}

	return txt_errors.NewErrUnknown()
}

func txtErrorDescription(err error) string {
	errTypeName := reflect.Indirect(reflect.ValueOf(err)).Type().Name()
	errDescription := txt_errors.ErrorDescription[errTypeName]
	return fmt.Sprintf("%s: %s", errTypeName, errDescription)
}

func (r ErrorResult) ExitCode() int {
	switch r.error().(type) {
	case *txt_errors.ErrBPMRevoked:
		return 3
	}
	return 1
}

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
/**
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
 */
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sort"

	cssLog "github.com/9elements/converged-security-suite/v2/pkg/log"
	belt "github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
	xlogrus "github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	fianoLog "github.com/linuxboot/fiano/pkg/log"

	"github.com/immune-gmbh/attestation-sdk/pkg/commands"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/commands/fwinfo"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/commands/list"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/commands/setup"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/commands/validate"
)

var (
	knownCommands = map[string]commands.Command{
		"fwinfo":   &fwinfo.Command{},
		"list":     &list.Command{},
		"setup":    &setup.Command{},
		"validate": &validate.Command{},
	}
	exitCode = 0
)

func usage(flagSet *flag.FlagSet) {
	flagSet.Usage()
	exitCode = 2 // the standard Go's exit-code on invalid flags
}

type flags struct {
	isQuiet            *bool
	loggingLevel       logger.Level
	remoteLoggingLevel *string
	tracePrefix        *string
}

func setupFlag() (*flag.FlagSet, *flags) {
	var f flags

	// Some packages leaves garbage in global `flag` without asking anybody,
	// so we have to use a separate flag set to do no display that garbage
	// in PrintDefaults().
	flagSet := flag.NewFlagSet("hwsecvalidator", flag.ExitOnError)
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "syntax: hwsecvalidator <command> [options] {arguments}\n")
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\nPossible commands:\n")

		// sort commands
		var commandList []string
		for commandName := range knownCommands {
			commandList = append(commandList, commandName)
		}
		sort.Strings(commandList)

		// display commands
		for _, commandName := range commandList {
			command := knownCommands[commandName]
			_, _ = fmt.Fprintf(flag.CommandLine.Output(), "    hwsecvalidator %-60s %s\n",
				fmt.Sprintf("%s %s", commandName, command.Usage()), command.Description())
		}
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\n")

		// display options
		flagSet.PrintDefaults()
	}

	f.loggingLevel = logger.LevelWarning // the default value
	flagSet.Var(&f.loggingLevel, "log-level", "logging level")
	f.isQuiet = flagSet.Bool("quiet", false, "suppress stdout")
	f.tracePrefix = flagSet.String("trace-prefix", "", "prepend traceID with this value; it is useful to understand which automation was responsible for this run")
	return flagSet, &f
}

func main() {
	// Parse arguments

	flagSet, flags := setupFlag()
	_ = flagSet.Parse(os.Args[1:])

	if flagSet.NArg() < 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: no command specified\n\n")
		usage(flagSet)
		return
	}

	// Initialize everything

	// Context
	ctx := logger.CtxWithLogger(
		context.Background(),
		xlogrus.Default().WithLevel(flags.loggingLevel),
	)

	if *flags.tracePrefix != "" {
		ctx = beltctx.WithTraceID(ctx, belt.TraceID(*flags.tracePrefix), belt.RandomTraceID())
	} else {
		ctx = beltctx.WithTraceID(ctx, belt.RandomTraceID())
	}

	defer func() {
		// We want both: custom exitcode (which could be set only via `os.Exit`)
		// and working `defer`-s. So we have to put os.Exit into a defer.

		// Though we do not want to avoid printing panics, so:
		if r := errmon.ObserveRecoverCtx(ctx, recover()); r != nil {
			debug.PrintStack()
			exitCode = 3
		}

		if ctx != nil {
			logger.FromCtx(ctx).Debugf("exitcode is %d", exitCode)
		}
		beltctx.Flush(ctx)
		os.Exit(exitCode)
	}()

	// Config
	cfg := commands.Config{
		IsQuiet: *flags.isQuiet,
	}
	commandName := flagSet.Arg(0)
	args := flagSet.Args()[1:]

	log := logger.FromCtx(ctx)

	span, ctx := tracer.StartChildSpanFromCtx(ctx, commandName)
	defer span.Finish()

	log.Debugf("cmd: '%s'; flags: %#+v; args: %v", commandName, flags, args)

	// suppressing fiano logs
	fianoLog.DefaultLogger = cssLog.NewFianoLogger(log, logger.LevelTrace)

	// Execute the command

	command := knownCommands[commandName]
	if command == nil {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: unknown command '%s'\n\n", commandName)
		usage(flagSet)
		return
	}

	flagSet = flag.NewFlagSet(commandName, flag.ExitOnError)
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "syntax: hwsecvalidator %s [options] %s\n\nOptions:\n",
			commandName, command.Usage())
		flagSet.PrintDefaults()
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\n")
	}

	flag.Usage = flagSet.Usage // for usageAndExit()

	command.SetupFlagSet(flagSet)
	_ = flagSet.Parse(args)
	err := command.Execute(ctx, cfg, flagSet.Args())

	// Process the error
	if err == nil {
		return
	}

	isSilentError := false
	exitCode = -1
	nestedErr := err
setExitCodeLoop:
	for nestedErr != nil {
		switch nestedErr := nestedErr.(type) {
		case commands.ErrArgs:
			_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: %v\n", nestedErr)
			usage(flagSet)
			return
		case commands.SilentError:
			isSilentError = true
		case commands.ExitCoder:
			exitCode = nestedErr.ExitCode()
			break setExitCodeLoop
		}
		nestedErr = errors.Unwrap(nestedErr)
	}

	if isSilentError {
		return
	}

	var errorString string
	var descriptioner commands.Descriptioner
	if errors.As(err, &descriptioner) {
		errorString = descriptioner.Description()
	} else {
		errorString = err.Error()
	}
	_, _ = fmt.Fprintf(os.Stderr, "EXITCODE: %d\n%s\n", exitCode, errorString)
}

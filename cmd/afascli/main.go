/**
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
 */
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sort"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/analyze"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/display_eventlog"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/display_info"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/display_tpm"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/dump"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/dump_registers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/fetch"
	pcr0sum "github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/pcr0_sum"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/report_host_configuration"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/search"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/search_report"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/txt_status"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/consts"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

var (
	knownCommands = map[string]commands.Command{
		"analyze":            &analyze.Command{},
		"report_host_config": &report_host_configuration.Command{},
		"display_eventlog":   &display_eventlog.Command{},
		"display_info":       &display_info.Command{},
		"display_tpm":        &display_tpm.Command{},
		"dump":               &dump.Command{},
		"dump_registers":     &dump_registers.Command{},
		"fetch":              &fetch.Command{},
		"pcr0_sum":           &pcr0sum.Command{},
		"search":             &search.Command{},
		"search_report":      &search_report.Command{},
		"txt_status":         &txt_status.Command{},
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
	remoteLoggingLevel logger.Level
	tracePrefix        *string
	netPprofAddr       *string
}

// fiano will log warning output when trying to decompress non-compressed data,
// but then continue to process it correctly as uncompressed. However it will
// log a warning that can confuse callers. Lower the errors logged to debug
// messages in our standard log, except if they are fatal, by wrapping them
// here. Any actual problems processing will get returned as an error.
type quietLogger struct {
	log logger.Logger
}

func (l quietLogger) Errorf(format string, args ...interface{}) {
	l.log.Debugf(format, args...)
}

func (l quietLogger) Fatalf(format string, args ...interface{}) {
	l.log.Fatalf(format, args...)
}

func (l quietLogger) Warnf(format string, args ...interface{}) {
	l.log.Debugf(format, args...)
}

func setupFlag() (*flag.FlagSet, *flags) {
	var f flags

	// Some packages leaves garbage in global `flag` without asking anybody,
	// so we have to use a separate flag set to do no display that garbage
	// in PrintDefaults().
	flagSet := flag.NewFlagSet("fwtool", flag.ExitOnError)
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "syntax: fwtool <command> [options] {arguments}\n")
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
			_, _ = fmt.Fprintf(flag.CommandLine.Output(), "    fwtool %-36s %s\n",
				fmt.Sprintf("%s %s", commandName, command.Usage()), command.Description())
		}
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\n")

		// display options
		flagSet.PrintDefaults()
	}

	f.loggingLevel = logger.LevelWarning // the default value
	flagSet.Var(&f.loggingLevel, "log-level", "logging level")
	f.remoteLoggingLevel = logger.LevelWarning // the default value
	flagSet.Var(&f.remoteLoggingLevel, "remote-log-level", "logging level used by the server to process the request")
	f.isQuiet = flagSet.Bool("quiet", false, "suppress stdout")
	f.tracePrefix = flagSet.String("trace-prefix", "", "prepend traceID with this value; it is useful to understand which automation was responsible for this run")
	f.netPprofAddr = flagSet.String("net-pprof-addr", "", "if non-empty then listens with net/http/pprof")
	return flagSet, &f
}

func main() {
	ctx, endFunc := context.WithCancel(context.Background())
	defer func() {
		// We want both: custom exitcode (which could be set only via `os.Exit`)
		// and working `defer`-s. So we have to put os.Exit into a defer.

		// Though we do not want to avoid printing panics, so:
		if event := errmon.ObserveRecoverCtx(ctx, recover()); event != nil {
			endFunc()
			beltctx.Flush(ctx)
			panic(event.PanicValue)
		}

		logger.FromCtx(ctx).Debugf("exitcode is %d", exitCode)
		endFunc()
		beltctx.Flush(ctx)
		os.Exit(exitCode)
	}()

	// Parse arguments

	flagSet, flags := setupFlag()
	_ = flagSet.Parse(os.Args[1:])

	if flagSet.NArg() < 1 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: no command specified\n\n")
		usage(flagSet)
		return
	}

	// Initialize everything
	ctx = observability.WithBelt(
		ctx,
		flags.loggingLevel,
		consts.ScubaLoggingDataset, "", consts.ScubaTracingDataset,
		*flags.tracePrefix,
		true,
	)

	if *flags.netPprofAddr != "" {
		go func() {
			err := http.ListenAndServe(*flags.netPprofAddr, nil)
			logger.FromCtx(ctx).Errorf("unable to start listening for https/net/pprof: %v", err)
		}()
	}

	commandName := flagSet.Arg(0)
	args := flagSet.Args()[1:]

	span, ctx := tracer.StartChildSpanFromCtx(ctx, commandName)
	defer span.Finish()

	cfg := commands.Config{
		IsQuiet: *flags.isQuiet,
		Context: ctx,
	}

	cfg.FirmwareWandOptions = append(cfg.FirmwareWandOptions, firmwarewand.OptionRemoteLogLevel(flags.remoteLoggingLevel))

	logger.FromCtx(ctx).Debugf("cmd: '%s'; flags: %#+v; args: %v", commandName, flags, args)

	// Unfortunately "fiano" does logging directly through "log", and there is
	// no other way to disable these logs. This downgrades all but fatal logs to
	// debug within our logger.FromCtx(ctx) framework.
	fianoLog.DefaultLogger = quietLogger{log: logger.FromCtx(ctx)}

	// Execute the command

	command := knownCommands[commandName]
	if command == nil {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "error: unknown command '%s'\n\n", commandName)
		usage(flagSet)
		return
	}

	flagSet = flag.NewFlagSet(commandName, flag.ExitOnError)
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "syntax: fwtool %s [options] %s\n\nOptions:\n",
			commandName, command.Usage())
		flagSet.PrintDefaults()
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "\n")
	}

	flag.Usage = flagSet.Usage // for usageAndExit()

	command.SetupFlagSet(flagSet)
	_ = flagSet.Parse(args)
	err := command.Execute(cfg, flagSet.Args())

	// Process the error
	if err == nil {
		return
	}

	isSilentError := false
	exitCode = 3
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
	if !isSilentError {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}

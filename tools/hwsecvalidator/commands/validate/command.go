package validate

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/registry"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	NotBooted    *bool
	SELs         *string
	DumpMethod   *string
	PathFlashrom *string
	PathAfulnx64 *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<test case> <original firmware>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "validates if the current state of the machine corresponds to the expected for the selected test case"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.NotBooted = flag.Bool("notbooted", false, "Tells the fwtest the host didn't boot")
	cmd.SELs = flag.String("sels", "", "path to sel events file")
	cmd.DumpMethod = flag.String("dump-method", "auto", "possible values: flashrom, afulnx64, devmem, auto")
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
	if len(args) < 2 {
		return commands.ErrArgs{Err: fmt.Errorf("error: no path to the firmare was specified")}
	}
	if len(args) > 2 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many parameters")}
	}
	testCaseName := args[0]
	origImagePath := args[1]

	testCases := registry.All()
	testCase := testCases.Find(testCaseName)
	if testCase == nil {
		return commands.ErrArgs{Err: fmt.Errorf("unknown test case '%s', available values are: %s",
			testCaseName,
			strings.Join(testCases.Names(), ","),
		)}
	}

	image, err := ioutil.ReadFile(origImagePath)
	if err != nil {
		return fmt.Errorf("unable to read to original image '%s': %w", origImagePath, err)
	}

	options := []types.Option{
		types.OptionFlashrom(cmd.FlashromOptions()),
	}
	if *cmd.NotBooted {
		options = append(options, types.OptionHostNotBooted{})
	}
	if len(*cmd.SELs) > 0 {
		b, err := ioutil.ReadFile(*cmd.SELs)
		if err != nil {
			return fmt.Errorf("unable to read SELs file '%s': '%w'", *cmd.SELs, err)
		}

		var sels []types.SEL
		if err := json.Unmarshal(b, &sels); err != nil {
			return fmt.Errorf("failed to parse SELs file '%s': '%w'", *cmd.SELs, err)
		}

		options = append(options, types.OptionForceSELEvents(sels))
	}

	err = testCase.Validate(cfg.Context, image, options...)
	if err != nil {
		return ErrTest{
			TestCase: testCase,
			Err:      err,
		}
	}

	return nil
}

type ErrTest struct {
	TestCase types.TestCase
	Err      error
}

// Description returns description of the test's result
func (err ErrTest) Description() string {
	var description string
	var descriptioner commands.Descriptioner
	if errors.As(err.Err, &descriptioner) {
		description = descriptioner.Description()
	} else {
		description = strings.ReplaceAll(err.Err.Error(), ": ", ": \n\t")
	}

	return fmt.Sprintf("SEVERITY: %s\nTEST CASE NAME: %s\nDESCRIPTION: %s",
		err.TestCase.Severity().FailureDescription(),
		types.NameOf(err.TestCase),
		description,
	)
}

func (err ErrTest) Error() string {
	return err.Err.Error()
}

// ExitCode implements commands.ExitCoder
func (err ErrTest) ExitCode() int {
	return err.TestCase.Severity().FailureExitCode()
}

func (err ErrTest) Unwrap() error {
	return err.Err
}

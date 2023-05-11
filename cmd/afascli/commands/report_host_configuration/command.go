package report_host_configuration

import (
	"flag"
	"fmt"

	fasclient "github.com/immune-gmbh/AttestationFailureAnalysisService/client"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"

	pcr0tool_commands "github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	firmwareAnalysisAddress *string
	firmwareVersion         *string
	firmwareDate            *string
	eventLog                *string
	localPCR0SHA1           *string
	registers               *string
	tpmDevice               *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "report current host configuration and output the expected PCR0 value"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	// It is called "Address" instead of "Tier" to add support of direct thrift
	// addresses in future (it will be determined by presence of a port, so
	// for direct addresses the format is: host:port)
	cmd.firmwareAnalysisAddress = flag.String("firmware-analysis-addr", "", "SMC tier of the firmware analysis service (default is '"+fasclient.DefaultSMCTier+"' with fallback on endpoints from '/tmp/yard_config.json')")

	cmd.eventLog = flag.String("event-log", "/sys/kernel/security/tpm0/binary_bios_measurements", "path to the binary EventLog")
	cmd.localPCR0SHA1 = flag.String("local-pcr0-sha1", "", "the value of local pcr0 sha1 value (allowed formats: binary, base64, hex)")
	cmd.firmwareVersion = flag.String("firmware-version", "", "the version of the firmware to use; empty value means to read SMBIOS values")
	cmd.firmwareDate = flag.String("firmware-date", "", "the date of the firmware to use; empty value means to read SMBIOS values")
	cmd.registers = flag.String("registers", "", "use status registers from JSON file (or dump them from TXT Public Space if empty value)")
	cmd.tpmDevice = flag.String("tpm-device", "", "optional tpm device type, values: "+pcr0tool_commands.TPMTypeCommandLineValues())
}

func (cmd Command) firmwarewandOptions() []firmwarewand.Option {
	return helpers.FirmwarewandOptions(*cmd.firmwareAnalysisAddress)
}

func (cmd Command) flagEventLog() string {
	return *cmd.eventLog
}

func (cmd Command) flagLocalPCR0() ([]byte, error) {
	return helpers.ConvertUserInputPCR(*cmd.localPCR0SHA1)
}

func (cmd Command) flagFirmwareVersion() string {
	return *cmd.firmwareVersion
}

func (cmd Command) flagFirmwareDate() string {
	return *cmd.firmwareDate
}

func (cmd Command) flagTPMDevice() (tpmdetection.Type, error) {
	if len(*cmd.tpmDevice) == 0 {
		return tpmdetection.TypeNoTPM, nil
	}
	return tpmdetection.FromString(*cmd.tpmDevice)
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(cfg commands.Config, args []string) error {
	fwWand, err := firmwarewand.New(cfg.Context, append(cfg.FirmwareWandOptions, cmd.firmwarewandOptions()...)...)
	if err != nil {
		return fmt.Errorf("unable to initialize a firmwarewand: %w", err)
	}
	defer fwWand.Close()

	localPCR0, err := cmd.flagLocalPCR0()
	if err != nil {
		return fmt.Errorf("unable to parse provided PCR0 SHA1 value: %w", err)
	}

	tpmDevice, err := cmd.flagTPMDevice()
	if err != nil {
		return fmt.Errorf("failed to parse input: %w", err)
	}

	var tpmEventlog *tpmeventlog.TPMEventLog
	pathToEventlog := cmd.flagEventLog()
	if len(pathToEventlog) > 0 {
		tpmEventlog, err = helpers.ParseTPMEventlog(*cmd.eventLog)
		if err != nil {
			logger.FromCtx(cfg.Context).Errorf("unable to get EventLog: %v", err)
		}
	}

	registers, err := helpers.ParseRegisters(*cmd.registers)
	if err != nil {
		logger.FromCtx(cfg.Context).Errorf("unable to get status registers: %v", err)
	}

	calculatedPCRs, err := fwWand.ReportHostConfiguration(
		tpmEventlog,
		registers,
		localPCR0,
		cmd.flagFirmwareVersion(),
		cmd.flagFirmwareDate(),
		tpmDevice,
	)
	if err != nil {
		return fmt.Errorf("failed to calculate PCR0: %w", err)
	}
	for _, pcr := range calculatedPCRs {
		fmt.Printf("Result PCR0: 0x%X\n", pcr)
	}
	return nil
}

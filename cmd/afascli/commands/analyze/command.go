package analyze

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/apcbsectokens/report/generated/apcbsecanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/biosrtmvolume/report/generated/biosrtmanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/pspsignature/report/generated/pspsignanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/generated/diffanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm/report/generated/intelacmanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/reproducepcr/report/generated/reproducepcranalysis"
	xregisters "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/registers"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/afascli/commands/analyze/format"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/afascli/commands/display_eventlog"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/afascli/commands/dump"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/afascli/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/dmidecode"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/tpm"

	pcr0tool_commands "github.com/9elements/converged-security-suite/v2/cmd/pcr0tool/commands"
	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/fatih/color"
	"github.com/google/go-tpm/tpm2"
	"github.com/ulikunitz/xz"
)

// DumpFormat specifies dump options
type DumpFormat string

const (
	// DumpFormatNone means do not dump
	DumpFormatNone DumpFormat = ""
	// DumpFormatJSON means to dump in json format
	DumpFormatJSON DumpFormat = "json"
	// DumpFormatBinary means to dump in binary (base64 encoded) format
	DumpFormatBinary DumpFormat = "binary"
)

type dumpCommand = dump.Command

// Command is the implementation of `commands.Command`.
type Command struct {
	dumpCommand
	analyzers               analyzersFlag
	eventLog                *string
	expectPCR0              *string
	afasEndpoint            *string
	firmwareRTPFilename     *string
	firmwareEverstoreHandle *string
	firmwareVersion         *string
	firmwareDate            *string
	registers               *string
	tpmDevice               *string
	flow                    *string
	localhostRequest        *bool
	showNotApplicable       *bool
	dumpRequest             *string
	useRequest              *string
	outputJSON              *bool
	outputFormat            *string
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<path to the image>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "launches selected analyzers: " + knownAnalyzersArg()
}

// Registers returns status registers according to flag '-registers' and '-localhost'
func (cmd Command) Registers() (registers.Registers, bool, error) {
	if len(*cmd.registers) > 0 {
		regs, err := helpers.ParseRegisters(*cmd.registers)
		return regs, true, err
	} else if *cmd.localhostRequest {
		regs, err := xregisters.LocalRegisters()
		return regs, false, err
	}
	return nil, false, nil
}

// TPMDevice returns TPM device according to flag '-tpm-device' and '-localhost'
func (cmd Command) TPMDevice() (tpmdetection.Type, bool, error) {
	if len(*cmd.tpmDevice) > 0 {
		tpmDevice, err := tpmdetection.FromString(*cmd.tpmDevice)
		return tpmDevice, true, err
	} else if *cmd.localhostRequest {
		tpmDevice, err := tpmdetection.Local()
		return tpmDevice, false, err
	}
	return tpmdetection.TypeNoTPM, false, nil
}

// EventLog returns a parsed TPM Event Log defined by path through flag '-event-log'.
func (cmd Command) EventLog() (*tpmeventlog.TPMEventLog, error) {
	eventlogPath := *cmd.eventLog
	if *cmd.localhostRequest && len(*cmd.eventLog) == 0 {
		eventlogPath = display_eventlog.DefaultEventlogLocation
	}
	if len(eventlogPath) == 0 {
		return nil, nil
	}
	return helpers.ParseTPMEventlog(eventlogPath)
}

// ExpectPCR0 returns a PCR0 defined by path flag '-expect-pcr0' and '-localhost'
func (cmd Command) ExpectPCR0() ([]byte, bool, error) {
	if len(*cmd.expectPCR0) > 0 {
		pcr0, err := helpers.ConvertUserInputPCR(*cmd.expectPCR0)
		return pcr0, true, err
	} else if *cmd.localhostRequest {
		var (
			localPCR0 []byte
			err       error
		)
		for _, alg := range []tpm2.Algorithm{tpm2.AlgSHA256, tpm2.AlgSHA1} {
			localPCR0, err = tpm.ReadPCRFromTPM(0, alg)
			if err == nil {
				return localPCR0, false, nil
			}
		}
		return nil, false, err
	}
	return nil, false, nil
}

// FlagFlow returns the value of the flag "flow"
func (cmd Command) FlagFlow() (pcr.Flow, error) {
	return pcr.FlowFromString(*cmd.flow)
}

// FlagUseRequest parses the file defined in `-use-request` as the AnalyzeRequest to be sent.
// Returns nil (without error) if the flag is empty.
// TODO: consider splitting `analyze` to `scan` and `analyze`
func (cmd Command) FlagUseRequest(ctx context.Context) (*afas.AnalyzeRequest, error) {
	if *cmd.useRequest == "" {
		return nil, nil
	}

	f, err := os.Open(*cmd.useRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to open file '%s': %w", *cmd.useRequest, err)
	}

	r := base64.NewDecoder(base64.StdEncoding, f)
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("unable to decode base64 from file '%s': %w", *cmd.useRequest, err)
	}

	request := afas.AnalyzeRequest{}
	err = helpers.DeserialiseThrift(ctx, b, &request)
	if err != nil {
		return nil, fmt.Errorf("unable to parse an %T from file '%s': %w", request, *cmd.useRequest, err)
	}
	return &request, nil
}

// FirmwareVersionDate returns information about firmware version/date based on flags '-firmware-version' and '-localhost' as well as optional input args
func (cmd Command) FirmwareVersionDate(ctx context.Context, actualFirmware []byte, actualImageMetaData *afas.FirmwareImageMetadata) ([]afas.FirmwareVersion, error) {
	if len(*cmd.firmwareVersion) > 0 {
		return []afas.FirmwareVersion{
			{
				Version: *cmd.firmwareVersion,
				Date:    *cmd.firmwareDate,
			},
		}, nil
	}
	// Try actualFirmware first (as we should take original firmware that matches it)
	// Try local firmware DMI Table (if we do analysis for a local host)
	// Try information found in Manifold (Manifold may store old/outdated information)
	var getFirmwareVersion []func() (string, string, error)
	if len(actualFirmware) > 0 {
		getFirmwareVersion = append(getFirmwareVersion, func() (string, string, error) {
			actualDMI, err := dmidecode.DMITableFromFirmwareImage(actualFirmware)
			if err != nil {
				logger.FromCtx(ctx).Errorf("Failed to get DMI Table from actual firmware: %v", err)
				return "", "", err
			}
			biosInfo := actualDMI.BIOSInfo()
			return biosInfo.Version, biosInfo.ReleaseDate, nil
		})
	}
	if *cmd.localhostRequest {
		getFirmwareVersion = append(getFirmwareVersion, func() (string, string, error) {
			localDMI, err := dmidecode.LocalDMITable()
			if err != nil {
				logger.FromCtx(ctx).Errorf("Failed to get local DMI Table: %v", err)
				return "", "", err
			}
			biosInfo := localDMI.BIOSInfo()
			return biosInfo.Version, biosInfo.ReleaseDate, nil
		})
	}
	if actualImageMetaData != nil && actualImageMetaData.Version != nil && actualImageMetaData.ReleaseDate != nil {
		getFirmwareVersion = append(getFirmwareVersion, func() (string, string, error) {
			return *actualImageMetaData.Version, *actualImageMetaData.ReleaseDate, nil
		})
	}

	var (
		result    []afas.FirmwareVersion
		resultErr errors.MultiError
	)
	for _, getter := range getFirmwareVersion {
		firmwareVersion, firmwareDate, err := getter()
		if err != nil {
			resultErr.Add(err)
			continue
		}
		result = append(result, afas.FirmwareVersion{
			Version: firmwareVersion,
			Date:    firmwareDate,
		})
		trimmedVersion := strings.TrimSpace(firmwareVersion)
		if trimmedVersion != firmwareVersion {
			result = append(result, afas.FirmwareVersion{
				Version: trimmedVersion,
				Date:    firmwareDate,
			})
		}
	}
	return result, resultErr.ReturnValue()
}

// DumpRequestFormat returns required Analyze request dump format or an error
func (cmd Command) DumpRequestFormat() (DumpFormat, error) {
	switch strings.ToLower(*cmd.dumpRequest) {
	case string(DumpFormatNone):
		return DumpFormatNone, nil
	case string(DumpFormatJSON):
		return DumpFormatJSON, nil
	case string(DumpFormatBinary):
		return DumpFormatBinary, nil
	}
	return DumpFormatNone, fmt.Errorf("invalid dump request format: '%s'", *cmd.dumpRequest)
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.dumpCommand.SetupFlagSet(flag)

	flag.Var(&cmd.analyzers, "analyzer", "List of analyzers to start, values: "+knownAnalyzersArg())
	cmd.afasEndpoint = flag.String("afas-endpoint", "", "")
	cmd.firmwareVersion = flag.String("firmware-version", "", "the version of the firmware to compare with; empty value means to read SMBIOS values")
	cmd.firmwareDate = flag.String("firmware-date", "", "the date of the firmware to compare with; empty value means to read SMBIOS values")
	cmd.eventLog = flag.String("event-log", "", "path to the binary EventLog")
	cmd.expectPCR0 = flag.String("expect-pcr0", "", "if you need information why PCR0 does not match the one you expect then pass the expected value here (allowed formats: binary, base64, hex); by default it reads the PCR0 value from TPM")
	cmd.registers = flag.String("registers", "", "use status registers from JSON file (or dump them from TXT Public Space if empty value)")
	cmd.tpmDevice = flag.String("tpm-device", "", "optional tpm device type, values: "+pcr0tool_commands.TPMTypeCommandLineValues())
	cmd.flow = flag.String("flow", pcr.FlowAuto.String(), "desired measurements flow, values: "+pcr0tool_commands.FlowCommandLineValues())
	cmd.localhostRequest = flag.Bool("localhost", false, "specified whether request is made for localhost environment")
	cmd.showNotApplicable = flag.Bool("show-not-applicable", false, "specifies whether to show not applicable analyzers result")
	cmd.outputJSON = flag.Bool("json", false, "prints the result AnalyzeResult thrift structure in json format")

	// TODO: Consider splitting "afascli analyze" to "afascli scan" and "afascli analyze".
	//       The "scan" should gather all the information, but do not send it anywhere,
	//       while "analyze" should send the gathered info for analysis.
	//       Otherwise "afascli analyze" is trying to cover too many too different use cases and becomes overloaded.
	cmd.dumpRequest = flag.String("dump-request", "", "prints the AnalyzeRequest in json or binary format. No Analyze API is invoked")
	cmd.useRequest = flag.String("use-request", "", "use an AnalyzeRequest from file, instead; it supports only the binary format, yet")
	cmd.outputFormat = flag.String("format", "", "output format using Go template language; supported pre-defined templates: '__short__' [incompatible with -json]")
}

// FirmwarewandOptions returns firmwarewand.Option slice
// which should be used according to passed flags.
func (cmd Command) FirmwarewandOptions() []firmwarewand.Option {
	return append(helpers.FirmwarewandOptions(*cmd.afasEndpoint), firmwarewand.OptionFlashromOptions(cmd.FlashromOptions()))
}

// TODO: Consider splitting "afascli analyze" to "afascli scan" and "afascli analyze".
//
//	The "scan" should gather all the information, but do not send it anywhere,
//	while "analyze" should send the gathered info for analysis.
//	Otherwise "afascli analyze" is trying to cover too many too different use cases and becomes overloaded.
func (cmd Command) buildAnalyzeRequest(
	ctx context.Context,
	cfg commands.Config,
	fwWand *firmwarewand.FirmwareWand,
	args []string,
) (*afas.AnalyzeRequest, error) {
	var actualFirmwareFile string
	if len(args) > 0 {
		actualFirmwareFile = args[0]
	}

	if len(cmd.analyzers) == 0 {
		cmd.analyzers = knownAnalyzers
	}
	for _, analyzer := range cmd.analyzers {
		var found bool
		for _, knownAnalyzer := range knownAnalyzers {
			if knownAnalyzer == analyzer {
				found = true
				break
			}
		}

		if !found {
			return nil, commands.ErrArgs{Err: fmt.Errorf("unknown analyzer: %s, use one of %s", analyzer, knownAnalyzersArg())}
		}
	}

	var (
		actualFirmware     []byte
		actualFirmwareMeta *afas.FirmwareImageMetadata
		err                error
	)

	if len(actualFirmwareFile) > 0 {
		actualFirmware, err = ioutil.ReadFile(actualFirmwareFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file '%s': %w", actualFirmware, err)
		}
	} else if *cmd.localhostRequest {
		actualFirmware, err = fwWand.Dump(ctx)
		if err != nil {
			logger.FromCtx(ctx).Errorf("Failed to dump local firmware: %v", err)
		}
		logger.FromCtx(ctx).Infof("Dumped local firmware of '%d' bytes", len(actualFirmware))
	}

	if len(actualFirmware) > 0 {
		actualFirmwareMeta = fwWand.FindImage(ctx, actualFirmware)
	}

	firmwareVersions, err := cmd.FirmwareVersionDate(ctx, actualFirmware, actualFirmwareMeta)
	if err != nil {
		logger.FromCtx(ctx).Errorf("Failed to obtain firmware version/date: %v", err)
	}

	// Some of the items in firmwareVersions could contain invalid information, check versions in AFAS
	var firmwareVersion, firmwareDate string
	if checkFwResult, err := fwWand.CheckFirmwareVersion(ctx, firmwareVersions); err != nil {
		if len(firmwareVersions) > 0 {
			firmwareVersion = firmwareVersions[0].Version
			firmwareDate = firmwareVersions[0].Date
			logger.FromCtx(ctx).Errorf("Failed to check firmware versions, use: %s/%s", firmwareVersion, firmwareDate)
		}
	} else {
		for idx, exists := range checkFwResult {
			if exists {
				firmwareVersion = firmwareVersions[idx].Version
				firmwareDate = firmwareVersions[idx].Date
				logger.FromCtx(ctx).Infof("Use valid firmware version/date: %s/%s", firmwareVersion, firmwareDate)
				break
			}
		}
	}

	registers, userInput, err := cmd.Registers()
	if err != nil {
		if registers == nil {
			logger.FromCtx(ctx).Errorf("Failed to obtain registers: %v", err)
		} else {
			// TODO: print error if some important registers are not obtained
			logger.FromCtx(ctx).Debugf("Failed to obtain registers: %v", err)
		}
		if userInput {
			return nil, err
		}
	}

	tpmDevice, userInput, err := cmd.TPMDevice()
	if err != nil {
		logger.FromCtx(ctx).Errorf("Failed to obtain TPM device: %v", err)
		if userInput {
			return nil, err
		}
	}

	eventlog, err := cmd.EventLog()
	if err != nil {
		logger.FromCtx(ctx).Errorf("Failed to obtain TPM eventlog: %v", err)
		return nil, err
	}

	expectPCR0, userInput, err := cmd.ExpectPCR0()
	if err != nil {
		logger.FromCtx(ctx).Errorf("Failed to obtain expected PCR0: %v", err)
		if userInput {
			return nil, err
		}
	}

	flow, err := cmd.FlagFlow()
	if err != nil {
		logger.FromCtx(ctx).Errorf("Failed to obtain measurements flow: %v", err)
		return nil, err
	}

	requestBuilder := firmwarewand.NewAnalyzeRequestBuilder()
	if *cmd.localhostRequest {
		if err := requestBuilder.AddLocalHostInfo(); err != nil {
			return nil, fmt.Errorf("failed to add local host info: %w", err)
		}
	}

	var actualImage afas.FirmwareImage
	if len(*cmd.firmwareRTPFilename) > 0 {
		actualImage.Filename = cmd.firmwareRTPFilename
	} else if len(*cmd.firmwareEverstoreHandle) > 0 {
		actualImage.EverstoreHandle = cmd.firmwareEverstoreHandle
	} else if actualFirmwareMeta != nil && len(actualFirmwareMeta.ImageID) > 0 {
		logger.FromCtx(ctx).Infof("Use manifold image ID: %X", actualFirmwareMeta.ImageID)
		actualImage.ManifoldID = actualFirmwareMeta.ImageID
	} else if len(actualFirmware) > 0 {
		compressedImage, err := compressXZ(actualFirmware)
		// this should not happen as all images should be compressed. Treat as a fatal error
		if err != nil {
			logger.FromCtx(ctx).Errorf("Failed to compress actual firmware image: %v", err)
			return nil, err
		}
		actualImage.Blob = &afas.CompressedBlob{
			Blob:        compressedImage,
			Compression: afas.CompressionType_XZ,
		}
	}

	var originalImage *afas.FirmwareImage
	if len(firmwareVersion) == 0 {
		originalImage = &actualImage
	}

	for _, analyzer := range cmd.analyzers {
		switch analyzer {
		case diffanalysis.DiffMeasuredBootAnalyzerID:
			err = requestBuilder.AddDiffMeasuredBootInput(
				firmwareVersion,
				firmwareDate,
				originalImage,
				actualImage,
				registers,
				tpmDevice,
				eventlog,
				expectPCR0,
			)
			if err != nil {
				color.New(color.FgRed).Printf("Failed to add measured boot input request: %v\n", err)
			}
		case intelacmanalysis.IntelACMAnalyzerID:
			err = requestBuilder.AddIntelACMInput(
				firmwareVersion,
				firmwareDate,
				originalImage,
				actualImage,
			)
			if err != nil {
				color.New(color.FgRed).Printf("Failed to add measured intel ACM input request: %v\n", err)
			}
		case reproducepcranalysis.ReproducePCRAnalyzerID:
			err = requestBuilder.AddReproducePCRInput(
				firmwareVersion,
				firmwareDate,
				originalImage,
				actualImage,
				registers,
				tpmDevice,
				eventlog,
				flow,
				expectPCR0,
			)
			if err != nil {
				color.New(color.FgRed).Printf("Failed to add reproduced PCR input request: %v\n", err)
			}
		case pspsignanalysis.PSPSignatureAnalyzerID:
			err = requestBuilder.AddPSPSignatureInput(
				&actualImage,
			)
			if err != nil {
				color.New(color.FgRed).Printf("Failed to add PSP signature input request: %v\n", err)
			}
		case biosrtmanalysis.BIOSRTMVolumeAnalyzerID:
			err = requestBuilder.AddBIOSRTMVolumeInput(
				&actualImage,
			)
			if err != nil {
				color.New(color.FgRed).Printf("Failed to add BIOS RTM Volume input request: %v\n", err)
			}
		case apcbsecanalysis.APCBSecurityTokensAnalyzerID:
			err = requestBuilder.AddAPCBSecurityTokensInput(
				&actualImage,
			)
			if err != nil {
				color.New(color.FgRed).Printf("Failed to add BIOS RTM Volume input request: %v\n", err)
			}
		default:
			return nil, fmt.Errorf("not supported analyzer: %s", analyzer)
		}
	}

	return requestBuilder.GetThrift(), nil
}

// OutputTemplate returns the template for output (or nil if it is not set).
func (cmd Command) OutputTemplate() (*template.Template, error) {
	if len(*cmd.outputFormat) == 0 {
		return nil, nil
	}
	var outputTemplate *template.Template
	var err error
	switch {
	case *cmd.outputFormat == "__short__":
		shortTemplate := `TraceID: {{ first .TraceIDs }}{{printf "\n"}}` +
			`{{if ne (len .JobID) 0}}JobID: {{ asUUID .JobID }}{{printf "\n"}}{{ end }}`
		outputTemplate, err = template.New("").Funcs(templateFuncs).Parse(shortTemplate)
	default:
		outputTemplate, err = template.New("").Funcs(templateFuncs).Parse(*cmd.outputFormat)
	}
	if err != nil {
		return nil, commands.ErrArgs{Err: fmt.Errorf("invalid -format value: %w", err)}
	}
	return outputTemplate, nil
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, cfg commands.Config, args []string) error {
	if len(args) > 2 {
		return commands.ErrArgs{Err: fmt.Errorf("unexpected number of arguments: %d", len(args))}
	}
	if (len(*cmd.firmwareVersion) > 0) != (len(*cmd.firmwareDate) > 0) {
		return commands.ErrArgs{Err: fmt.Errorf("both firmware version and date should be specified or not")}
	}
	if len(*cmd.outputFormat) > 0 && *cmd.outputJSON {
		return commands.ErrArgs{Err: fmt.Errorf("flags -json and -format are incompatible")}
	}

	outputTemplate, err := cmd.OutputTemplate()
	if err != nil {
		return err
	}

	dumpRequestFormat, err := cmd.DumpRequestFormat()
	if err != nil {
		return err
	}

	fwWand, err := firmwarewand.New(ctx, append(cfg.FirmwareWandOptions, cmd.FirmwarewandOptions()...)...)
	if err != nil {
		return fmt.Errorf("unable to initialize a firmwarewand: %w", err)
	}
	defer func() {
		if err := fwWand.Close(); err != nil {
			fmt.Printf("Failed to close fwWand, err: %v", err)
		}
	}()

	request, err := cmd.FlagUseRequest(ctx)
	if err != nil {
		return commands.ErrArgs{Err: fmt.Errorf("unable to parse the -use-request flag: %w", err)}
	}
	if request == nil {
		request, err = cmd.buildAnalyzeRequest(ctx, cfg, fwWand, args)
		if err != nil {
			return err
		}
	}

	if dumpRequestFormat != DumpFormatNone {
		switch dumpRequestFormat {
		case DumpFormatJSON:
			resultJSON, err := json.Marshal(request)
			if err != nil {
				return fmt.Errorf("marshalling analyze request into json failed: %w", err)
			}
			fmt.Print(string(resultJSON))
		case DumpFormatBinary:
			serialized, err := helpers.SerialiseThrift(ctx, request)
			if err != nil {
				return fmt.Errorf("unable to serialize request data: %v", err)
			}

			output := base64.StdEncoding.EncodeToString(serialized)
			fmt.Println(output)
		default:
			return fmt.Errorf("unsupported request dump format: '%s'", dumpRequestFormat)
		}
	} else {
		result, err := fwWand.Analyze(ctx, request)
		if err != nil {
			return fmt.Errorf("analyze request failed: %w", err)
		}

		switch {
		case *cmd.outputJSON:
			resultJSON, err := json.Marshal(result)
			if err != nil {
				return fmt.Errorf("failed to marshal result: %w", err)
			}
			fmt.Print(string(resultJSON))
		case outputTemplate != nil:
			type Result = afas.AnalyzeResult_
			type outputData struct {
				*Result
				TraceIDs belt.TraceIDs
			}
			err = outputTemplate.Execute(os.Stdout, outputData{
				Result:   result,
				TraceIDs: beltctx.TraceIDs(ctx),
			})
			if err != nil {
				return fmt.Errorf("failed to format the result: %w", err)
			}
		default:
			format.HumanReadable(os.Stdout, *result, true, *cmd.showNotApplicable)
		}
	}
	return nil
}

func compressXZ(image []byte) ([]byte, error) {
	var compressed bytes.Buffer
	xzWriter, err := xz.NewWriter(&compressed)
	if err != nil {
		return nil, fmt.Errorf("unable to create XZ writer: %w", err)
	}
	_, err = xzWriter.Write(image)
	if err != nil {
		return nil, fmt.Errorf("unable to compress data with XZ: %w", err)
	}
	err = xzWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("unable to finalize the compression of data with XZ: %w", err)
	}
	return compressed.Bytes(), nil
}

type analyzersFlag []analysis.AnalyzerID

func (i *analyzersFlag) String() string {
	return "analyzers to use"
}

func (i *analyzersFlag) Set(value string) error {
	*i = append(*i, analysis.AnalyzerID(value))
	return nil
}

// supported analyzers by the tool
var knownAnalyzers = []analysis.AnalyzerID{
	diffanalysis.DiffMeasuredBootAnalyzerID,
	intelacmanalysis.IntelACMAnalyzerID,
	reproducepcranalysis.ReproducePCRAnalyzerID,
	pspsignanalysis.PSPSignatureAnalyzerID,
	biosrtmanalysis.BIOSRTMVolumeAnalyzerID,
	apcbsecanalysis.APCBSecurityTokensAnalyzerID,
}

func knownAnalyzersArg() string {
	result := make([]string, 0, len(knownAnalyzers))
	for _, analyzer := range knownAnalyzers {
		result = append(result, string(analyzer))
	}
	return strings.Join(result, "|")
}

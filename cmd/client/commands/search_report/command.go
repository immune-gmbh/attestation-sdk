package search_report

import (
	"flag"
	"fmt"
	"os"

	fasclient "libfb/go/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	analyzeformat "github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/commands/analyze/format"
	verbhelpers "github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/client/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/commands"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarewand"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	firmwareAnalysisAddress *string
	limit                   *uint64
	jobID                   *string
	assetID                 *uint64
	imageID                 types.ImageID
	showNotApplicable       *bool
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return "<-image-id=imageID|-asset-id=assetID|-job-id=jobID>"
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "fetch and display the report about a firmware image"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	// for "firmwareAnalysisAddress" see the comment in ../verify/command.go
	cmd.firmwareAnalysisAddress = flag.String("firmware-analysis-addr", "", "SMC tier of the firmware analysis service (default is '"+fasclient.DefaultSMCTier+"' with fallback on endpoints from '/tmp/yard_config.json')")

	cmd.limit = flag.Uint64("limit", 1, "maximal amount of entries to fetch and display (the order is reversed-chronological)")
	cmd.jobID = flag.String("job-id", "", "JobID to filter the reports by")
	cmd.assetID = flag.Uint64("asset-id", 0, "AssetID to filter the reports by")
	flag.Var(&cmd.imageID, "image-id", "ImageID to filter the reports by")
	cmd.showNotApplicable = flag.Bool("show-not-applicable", false, "specifies whether to show not applicable analyzers result")
}

func (cmd Command) firmwarewandOptions() []firmwarewand.Option {
	return verbhelpers.FirmwarewandOptions(*cmd.firmwareAnalysisAddress)
}

func (cmd Command) flagJobID() (*types.JobID, error) {
	if *cmd.jobID == "" {
		return nil, nil
	}
	jobID, err := types.ParseJobID(*cmd.jobID)
	if err != nil {
		return nil, err
	}
	return &jobID, nil
}

func (cmd Command) flagAssetID() *uint64 {
	if *cmd.assetID == 0 {
		return nil
	}

	return cmd.assetID
}

func (cmd Command) flagImageID() *types.ImageID {
	if cmd.imageID.IsZero() {
		return nil
	}

	return &cmd.imageID
}

func (cmd Command) flagLimit() uint64 {
	return *cmd.limit
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(cfg commands.Config, args []string) error {
	if len(args) > 0 {
		return commands.ErrArgs{Err: fmt.Errorf("an extra parameter found")}
	}

	var searchFilters afas.SearchReportFilters

	jobID, err := cmd.flagJobID()
	if err != nil {
		return commands.ErrArgs{Err: fmt.Errorf("unable to parse -job-id: %w", err)}
	}
	if jobID != nil {
		searchFilters.JobID = jobID[:]
	}

	if assetID := cmd.flagAssetID(); assetID != nil {
		searchFilters.AssetID = &[]int64{int64(*assetID)}[0]
	}

	if imageID := cmd.flagImageID(); imageID != nil {
		searchFilters.ActualFirmware = &afas.SearchFirmwareFilters{
			ImageID: imageID[:],
		}
	}

	fwWand, err := firmwarewand.New(cfg.Context, append(cfg.FirmwareWandOptions, cmd.firmwarewandOptions()...)...)
	if err != nil {
		return fmt.Errorf("unable to initialize a firmwarewand: %w", err)
	}

	result, err := fwWand.SearchReport(searchFilters, cmd.flagLimit())
	if err != nil {
		return fmt.Errorf("unable to perform SearchReport request: %w", err)
	}

	if len(result.Found) == 0 {
		fmt.Printf("Have not found any entries with filters: %#+v\n", searchFilters)
		return nil
	}

	for _, result := range result.Found {
		analyzeformat.HumanReadable(os.Stdout, *result, true, *cmd.showNotApplicable)
	}

	return nil
}

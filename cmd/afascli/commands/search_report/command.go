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

package search_report

import (
	"context"
	"flag"
	"fmt"
	"os"

	analyzeformat "github.com/immune-gmbh/attestation-sdk/cmd/afascli/commands/analyze/format"
	verbhelpers "github.com/immune-gmbh/attestation-sdk/cmd/afascli/helpers"
	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/pkg/commands"
	"github.com/immune-gmbh/attestation-sdk/pkg/firmwarewand"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"
)

// Command is the implementation of `commands.Command`.
type Command struct {
	afasEndpoint      *string
	limit             *uint64
	jobID             *string
	assetID           *uint64
	imageID           types.ImageID
	showNotApplicable *bool
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
	cmd.afasEndpoint = flag.String("afas-endpoint", "http://localhost:17545", "")
	cmd.limit = flag.Uint64("limit", 1, "maximal amount of entries to fetch and display (the order is reversed-chronological)")
	cmd.jobID = flag.String("job-id", "", "JobID to filter the reports by")
	cmd.assetID = flag.Uint64("asset-id", 0, "AssetID to filter the reports by")
	flag.Var(&cmd.imageID, "image-id", "ImageID to filter the reports by")
	cmd.showNotApplicable = flag.Bool("show-not-applicable", false, "specifies whether to show not applicable analyzers result")
}

func (cmd Command) firmwarewandOptions() []firmwarewand.Option {
	return verbhelpers.FirmwarewandOptions(*cmd.afasEndpoint)
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
func (cmd Command) Execute(ctx context.Context, cfg commands.Config, args []string) error {
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

	fwWand, err := firmwarewand.New(ctx, append(cfg.FirmwareWandOptions, cmd.firmwarewandOptions()...)...)
	if err != nil {
		return fmt.Errorf("unable to initialize a firmwarewand: %w", err)
	}

	result, err := fwWand.SearchReport(ctx, searchFilters, cmd.flagLimit())
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

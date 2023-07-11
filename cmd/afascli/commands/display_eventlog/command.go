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

package display_eventlog

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/immune-gmbh/attestation-sdk/cmd/afascli/commands/display_eventlog/format"
	"github.com/immune-gmbh/attestation-sdk/pkg/commands"
	"github.com/immune-gmbh/attestation-sdk/pkg/xtpmeventlog"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	manifest "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
)

const DefaultEventlogLocation = "/sys/kernel/security/tpm0/binary_bios_measurements"

// Command is the implementation of `commands.Command`.
type Command struct {
	eventLog *string
	pcrIndex *int64
	hashAlgo *int64
	calcPCR  *bool
	format   flagFormat
}

// Usage prints the syntax of arguments for this command
func (cmd Command) Usage() string {
	return ""
}

// Description explains what this verb commands to do
func (cmd Command) Description() string {
	return "display TPM Event Log"
}

// SetupFlagSet is called to allow the command implementation
// to setup which option flags it has.
func (cmd *Command) SetupFlagSet(flag *flag.FlagSet) {
	cmd.eventLog = flag.String("event-log", DefaultEventlogLocation, "path to the binary EventLog")
	cmd.pcrIndex = flag.Int64("pcr-index", -1, "filter for specific PCR register")
	cmd.hashAlgo = flag.Int64("hash-algo", 0, "filter by hash algorithm")
	cmd.calcPCR = flag.Bool("calc-pcr", false, "should calculate the PCR value")
	flag.Var(&cmd.format, "format", "select output format, allowed values: plaintext-oneline, plaintext-multiline")
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd Command) Execute(ctx context.Context, cfg commands.Config, args []string) error {
	if len(args) > 0 {
		return commands.ErrArgs{Err: fmt.Errorf("error: too many parameters")}
	}

	eventLogFile, err := os.Open(*cmd.eventLog)
	if err != nil {
		return fmt.Errorf("unable to open EventLog '%s': %w", *cmd.eventLog, err)
	}

	eventLog, err := tpmeventlog.Parse(eventLogFile)
	if err != nil {
		return fmt.Errorf("unable to parse EventLog '%s': %w", *cmd.eventLog, err)
	}

	if *cmd.calcPCR && (*cmd.pcrIndex == -1 || *cmd.hashAlgo == 0) {
		return fmt.Errorf("to calculate a PCR value it is required to set PCR index (-pcr-index) and hash algorithm (-hash-algo)")
	}

	var filterPCRIndex *pcr.ID
	var filterHashAlgo *tpmeventlog.TPMAlgorithm
	if *cmd.pcrIndex != -1 {
		filterPCRIndex = format.PCRIndexPtr(pcr.ID(*cmd.pcrIndex))
	}
	if *cmd.hashAlgo != 0 {
		filterHashAlgo = format.HashAlgoPtr(tpmeventlog.TPMAlgorithm(*cmd.hashAlgo))
	}
	fmt.Print(format.EventLog(eventLog, filterPCRIndex, filterHashAlgo, "", cmd.format == flagFormatPlaintextMultiline))

	if *cmd.pcrIndex != -1 && *cmd.hashAlgo != 0 {
		pcr0DataLog, _, _ := xtpmeventlog.ExtractPCR0DATALog(eventLog, tpmeventlog.TPMAlgorithm(*cmd.hashAlgo))
		if pcr0DataLog != nil {
			measurement, _ := pcr0DataLog.Measurement(manifest.Algorithm(*cmd.hashAlgo))
			fmt.Printf("\n")
			if measurement != nil {
				fmt.Printf("PCR0_DATA measurement original data is: %X\n", measurement.CompileMeasurableData(nil))
			}
			for _, pcr0DataOrig := range pcr0DataLog.OriginalPCR0.Digests {
				if pcr0DataOrig.HashAlg == manifest.Algorithm(*cmd.hashAlgo) {
					fmt.Printf("PCR0 value after PCR0_DATA measurement is: %X\n", pcr0DataOrig.Digest.Digest)
					break
				}
			}
			fmt.Printf("\n")
		}
	}

	if *cmd.calcPCR {
		calculatedValue, err := tpmeventlog.Replay(eventLog, pcr.ID(*cmd.pcrIndex), tpmeventlog.TPMAlgorithm(*cmd.hashAlgo), nil)
		if err != nil {
			return fmt.Errorf("unable to replay the PCR%d value: %w", *cmd.pcrIndex, err)
		}
		fmt.Printf("Calc\t%2d\t%10s\t%3d\t%X\t\n", *cmd.pcrIndex, "", *cmd.hashAlgo, calculatedValue)
	}

	return nil
}

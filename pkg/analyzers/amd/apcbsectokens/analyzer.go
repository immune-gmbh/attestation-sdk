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

package apcbsectokens

import (
	"context"
	"fmt"

	"github.com/linuxboot/fiano/pkg/amd/apcb"
	"github.com/linuxboot/fiano/pkg/amd/psb"

	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/amd/apcbsectokens/report/generated/apcbsecanalysis"

	"github.com/facebookincubator/go-belt/tool/logger"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

func init() {
	analysis.RegisterType((*apcbsecanalysis.CustomReport)(nil))
}

// ID represents the unique id of APCBSecurityTokens analyzer that checks BIOS
const ID analysis.AnalyzerID = apcbsecanalysis.APCBSecurityTokensAnalyzerID

// Input is an input structure required for analyzer
type Input struct {
	Firmware analysis.ActualPSPFirmware
}

// NewExecutorInput builds an analysis.Executor's input required for BIOSRTMVolume analyzer
func NewExecutorInput(
	actualFirmware analysis.Blob,
) (analysis.Input, error) {
	if actualFirmware == nil {
		return nil, fmt.Errorf("firmware image should be specified")
	}

	result := analysis.NewInput()
	result.AddActualFirmware(
		actualFirmware,
	)
	return result, nil
}

// Analyzer that verifies AMD's BIOS RTM Volume
type Analyzer struct{}

// New returns a new object of PSPSignature analyzer
func New() analysis.Analyzer[Input] {
	return &Analyzer{}
}

// ID implements the ID method required for analysis.Analyzer
func (analyzer *Analyzer) ID() analysis.AnalyzerID {
	return ID
}

// Analyze makes the APCB tokens gathering and analysis
func (analyzer *Analyzer) Analyze(ctx context.Context, in Input) (*analysis.Report, error) {
	log := logger.FromCtx(ctx)
	amdFw := in.Firmware.AMDFirmware()

	var custom apcbsecanalysis.CustomReport
	if amdFw.PSPFirmware().BIOSDirectoryLevel1 != nil {
		tokens, err := analyzer.getBIOSDirectoryTokens(ctx, amdFw, 1)
		if err != nil {
			log.Errorf("failed to process APCB tokens of BIOS directory level 1: %v", err)
			return nil, err
		}
		custom.DirectoryTokens = append(custom.DirectoryTokens, &apcbsecanalysis.BIOSDirectoryTokens{
			BIOSDirectoryLevel: 1,
			Tokens:             tokens,
		})
	} else {
		log.Infof("BIOS directory level 1 was not found")
	}

	if amdFw.PSPFirmware().BIOSDirectoryLevel2 != nil {
		tokens, err := analyzer.getBIOSDirectoryTokens(ctx, amdFw, 2)
		if err != nil {
			log.Errorf("failed to process APCB tokens of BIOS directory level 2: %v", err)
			return nil, err
		}
		custom.DirectoryTokens = append(custom.DirectoryTokens, &apcbsecanalysis.BIOSDirectoryTokens{
			BIOSDirectoryLevel: 2,
			Tokens:             tokens,
		})
	} else {
		log.Infof("BIOS directory level 2 was not found")
	}

	var result analysis.Report
	result.Custom = custom
	for _, dirInfo := range custom.DirectoryTokens {
		result.Issues = append(result.Issues, getTokensIssues(*dirInfo)...)
	}
	return &result, nil
}

func (analyzer *Analyzer) getBIOSDirectoryTokens(
	ctx context.Context,
	amdFw *amd_manifest.AMDFirmware,
	biosLevel uint,
) ([]*apcbsecanalysis.Token, error) {
	apcbEntries, err := psb.GetBIOSEntries(amdFw.PSPFirmware(), biosLevel, amd_manifest.APCBDataEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to get APCB binary entries of BIOS directory level %d: %w", biosLevel, err)
	}
	apcbBackupEntries, err := psb.GetBIOSEntries(amdFw.PSPFirmware(), biosLevel, amd_manifest.APCBDataBackupEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to get APCB backup binary entries of BIOS directory level %d: %w", biosLevel, err)
	}
	apcbEntries = append(apcbEntries, apcbBackupEntries...)

	var result []*apcbsecanalysis.Token
	for _, entry := range apcbEntries {
		data, err := psb.GetRangeBytes(amdFw.Firmware().ImageBytes(), entry.SourceAddress, uint64(entry.Size))
		if err != nil {
			return nil, fmt.Errorf("failed to get bytes of entry %s, instance id: %d of BIOS directory level %d",
				psb.BIOSEntryType(entry.Type), entry.Instance, biosLevel)
		}
		tokens, err := apcb.ParseAPCBBinaryTokens(data)
		if err != nil {
			return nil, fmt.Errorf("failed to get tokens of entry %s, instance id: %d of BIOS directory level %d",
				psb.BIOSEntryType(entry.Type), entry.Instance, biosLevel)
		}
		for _, token := range tokens {
			var tokenID apcbsecanalysis.TokenID
			switch token.ID {
			case apcb.TokenIDPSPMeasureConfig:
				tokenID = apcbsecanalysis.TokenID_PSPMeasureConfig
			case apcb.TokenIDPSPEnableDebugMode:
				tokenID = apcbsecanalysis.TokenID_PSPEnableDebugMode
			case apcb.TokenIDPSPErrorDisplay:
				tokenID = apcbsecanalysis.TokenID_PSPErrorDisplay
			case apcb.TokenIDPSPStopOnError:
				tokenID = apcbsecanalysis.TokenID_PSPStopOnError
			default:
				continue
			}

			var value apcbsecanalysis.TokenValue
			switch v := token.Value.(type) {
			case bool:
				value.Boolean = &v
			case uint8:
				signedByte := int8(v)
				value.Byte = &signedByte
			case uint16:
				signedWord := int16(v)
				value.Word = &signedWord
			case uint32:
				signedDWord := int32(v)
				value.DWord = &signedDWord
			default:
				return nil, fmt.Errorf("unknown token value type: %T", token.Value)
			}

			result = append(result, &apcbsecanalysis.Token{
				ID:           tokenID,
				PriorityMask: int8(token.PriorityMask),
				BoardMask:    int16(token.BoardMask),
				Value:        &value,
			})
		}
	}
	return result, nil
}

func getTokensOfID(id apcbsecanalysis.TokenID, tokens []*apcbsecanalysis.Token) []*apcbsecanalysis.Token {
	var result []*apcbsecanalysis.Token
	for _, token := range tokens {
		if token.ID == id {
			result = append(result, token)
		}
	}
	return result
}

func getTokensIssues(directoryTokens apcbsecanalysis.BIOSDirectoryTokens) []analysis.Issue {
	pspMeasureConfig := getTokensOfID(apcbsecanalysis.TokenID_PSPMeasureConfig, directoryTokens.Tokens)
	if len(pspMeasureConfig) == 0 {
		return []analysis.Issue{
			{
				Severity:    analysis.SeverityCritical,
				Description: fmt.Sprintf("No APCB_TOKEN_UID_PSP_MEASURE_CONFIG token is found in BIOS directory level %d", directoryTokens.BIOSDirectoryLevel),
			},
		}
	}

	var result []analysis.Issue
	for _, token := range pspMeasureConfig {
		if !token.Value.IsSetDWord() {
			result = append(result, analysis.Issue{
				Severity:    analysis.SeverityCritical,
				Description: fmt.Sprintf("APCB_TOKEN_UID_PSP_MEASURE_CONFIG token found in BIOS directory level %d has incorrect value type", directoryTokens.BIOSDirectoryLevel),
			})
			continue
		}

		if token.Value.GetDWord() != 1 {
			result = append(result, analysis.Issue{
				Severity: analysis.SeverityCritical,
				Description: fmt.Sprintf(
					"APCB_TOKEN_UID_PSP_MEASURE_CONFIG token found in BIOS directory level %d has bad value of '0x%X', expected: '0x1'",
					directoryTokens.BIOSDirectoryLevel,
					token.Value.GetDWord(),
				),
			})
		}
	}
	return result
}

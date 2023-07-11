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

package pspsignature

import (
	"context"
	"errors"
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/amd/pspsignature/report/generated/pspsignanalysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/amd/types/conv"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/amd/types/generated/psptypes"
	"github.com/linuxboot/fiano/pkg/amd/psb"

	"github.com/facebookincubator/go-belt/tool/logger"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

func init() {
	analysis.RegisterType((*pspsignanalysis.CustomReport)(nil))
}

// ID represents the unique id of PSPSignature analyzer that checks all PSP signatures for validity
const ID analysis.AnalyzerID = pspsignanalysis.PSPSignatureAnalyzerID

// Input is an input structure required for analyzer
type Input struct {
	Firmware analysis.ActualPSPFirmware
}

// NewExecutorInput builds an analysis.Executor's input required for IntelACM analyzer
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

// PSPSignature is analyzer that verifies all AMD's PSP signatures
type PSPSignature struct{}

// New returns a new object of PSPSignature analyzer
func New() analysis.Analyzer[Input] {
	return &PSPSignature{}
}

// ID implements the ID method required for analysis.Analyzer
func (analyzer *PSPSignature) ID() analysis.AnalyzerID {
	return ID
}

// Analyze makes the ACM gathering
func (analyzer *PSPSignature) Analyze(ctx context.Context, in Input) (*analysis.Report, error) {
	log := logger.FromCtx(ctx)
	pspFirmware := in.Firmware.AMDFirmware().PSPFirmware()
	if pspFirmware.PSPDirectoryLevel1 == nil {
		log.Infof("no PSP directory level 1 is found")

		items := []*pspsignanalysis.ValidatedItem{
			{
				Directory:         psptypes.DirectoryType_PSPTableLevel1,
				ValidationResult_: pspsignanalysis.Validation_NotFound,
			},
		}
		return &analysis.Report{
			Custom: pspsignanalysis.CustomReport{
				Items: items,
			},
			Issues: validatedItemsIssues(items),
		}, nil
	}

	result, err := analyzer.checkPSPEntriesSignatures(ctx, in.Firmware.AMDFirmware(), 1)
	if err != nil {
		log.Errorf("Failed to check PSP entries signatures for directories of level 1: %v", err)
		return nil, err
	}
	if pspFirmware.PSPDirectoryLevel2 != nil {
		level2Items, err := analyzer.checkPSPEntriesSignatures(ctx, in.Firmware.AMDFirmware(), 2)
		if err != nil {
			log.Errorf("Failed to check PSP entries signatures for directories of level 2: %v", err)
			return nil, err
		}
		result = append(result, level2Items...)
	}

	return &analysis.Report{
		Custom: pspsignanalysis.CustomReport{
			Items: result,
		},
		Issues: validatedItemsIssues(result),
	}, nil
}

// We will have a whitelist of items that should be signed and will keep analyzer that checks that all firmware types are known to us
var checkedPSPEntries = []uint32{
	uint32(amd_manifest.PSPBootloaderFirmwareEntry),
	uint32(psb.PSPRecoveryBootloader),
	uint32(psb.SMUOffChipFirmwareEntry),
	uint32(psb.SMUOffChipFirmware2Entry),
	uint32(psb.UnlockDebugImageEntry),
	uint32(psb.SecurityPolicyBinaryEntry),
	uint32(psb.MP5FirmwareEntry),
	uint32(psb.AGESABinary0Entry),
	uint32(psb.DXIOPHYSRAMFirmwareEntry),
	uint32(psb.DRTMTAEntry),
}

var checkedBIOSEntries = []uint32{
	uint32(amd_manifest.PMUFirmwareInstructionsEntry),
	uint32(amd_manifest.PMUFirmwareDataEntry),
}

func (analyzer *PSPSignature) checkPSPEntriesSignatures(
	ctx context.Context,
	amdFw *amd_manifest.AMDFirmware,
	level uint,
) ([]*pspsignanalysis.ValidatedItem, error) {
	log := logger.FromCtx(ctx)
	thriftPSPDirectory, err := conv.ThriftPSPDirectoryOfLevel(level)
	if err != nil {
		log.Errorf("Failed to get thrift PSP directory of level '%d': %v", level, err)
		return nil, err
	}

	var result []*pspsignanalysis.ValidatedItem
	keyDBEntry := psptypes.DirectoryEntry{
		PSPEntry: &[]psptypes.PSPDirectoryTableEntryType{psptypes.PSPDirectoryTableEntryType_KeyDatabaseEntry}[0],
	}

	keyDB, keyDBErr := psb.GetKeys(amdFw, level)
	if keyDBErr != nil {
		item, convErr := errorToValidatedItem(thriftPSPDirectory, &keyDBEntry, keyDBErr)
		if convErr != nil {
			log.Errorf("Failed to get validated item info for %v", keyDBErr)
			return nil, convErr
		}
		return []*pspsignanalysis.ValidatedItem{item}, nil
	}
	result = append(result, &pspsignanalysis.ValidatedItem{
		Directory:         thriftPSPDirectory,
		Entry:             &keyDBEntry,
		ValidationResult_: pspsignanalysis.Validation_Correct,
	})

	pspItems, err := analyzer.validatePSPDirectoryEntries(ctx, amdFw, keyDB, level, checkedPSPEntries)
	if err != nil {
		log.Errorf("Failed to validate PSP entries: %v", err)
		return nil, err
	}
	result = append(result, pspItems...)

	biosItems, err := analyzer.validateBIOSDirectoryEntries(ctx, amdFw, keyDB, level, checkedBIOSEntries)
	if err != nil {
		log.Errorf("Failed to validate BIOS entries: %v", err)
		return nil, err
	}
	result = append(result, biosItems...)
	return result, nil
}

func (analyzer *PSPSignature) validatePSPDirectoryEntries(
	ctx context.Context,
	amdFw *amd_manifest.AMDFirmware,
	keyDB psb.KeySet,
	level uint,
	pspEntries []uint32,
) ([]*pspsignanalysis.ValidatedItem, error) {
	log := logger.FromCtx(ctx)
	thriftPSPDirectory, err := conv.ThriftPSPDirectoryOfLevel(level)
	if err != nil {
		return nil, err
	}
	pspDirectory, err := psb.GetPSPDirectoryOfLevel(level)
	if err != nil {
		return nil, err
	}

	var result []*pspsignanalysis.ValidatedItem
	for _, checkedEntry := range pspEntries {
		pspDirectoryEntry := amd_manifest.PSPDirectoryTableEntryType(checkedEntry)
		directoryEntry := &psptypes.DirectoryEntry{
			PSPEntry: &[]psptypes.PSPDirectoryTableEntryType{conv.ToThriftPSPDirectoryTableEntryType(pspDirectoryEntry)}[0],
		}
		addEntryError := func(entryErr error) error {
			item, convErr := errorToValidatedItem(thriftPSPDirectory, directoryEntry, entryErr)
			if convErr != nil {
				log.Errorf("Failed to get validated item info for %v", convErr)
				return convErr
			}
			result = append(result, item)
			return nil
		}

		pspEntry, getEntryErr := psb.GetPSPEntry(amdFw.PSPFirmware(), level, pspDirectoryEntry)
		if getEntryErr != nil {
			// any item of checkedPSPEntries is optional
			if errors.As(getEntryErr, &psb.ErrNotFound{}) {
				log.Infof("PSP item %s of directory %s is not found", pspDirectoryEntry, pspDirectory)
			} else if err := addEntryError(getEntryErr); err != nil {
				return nil, err
			}
			continue
		}

		validationResult, validationErr := psb.ValidatePSPEntry(amdFw, keyDB, pspEntry.LocationOrValue, uint64(pspEntry.Size))
		if validationErr != nil {
			if err := addEntryError(validationErr); err != nil {
				return nil, err
			}
			continue
		}

		if validationResult.Error() != nil {
			if err := addEntryError(validationResult.Error()); err != nil {
				return nil, err
			}
		} else {
			result = append(result, &pspsignanalysis.ValidatedItem{
				Directory:         thriftPSPDirectory,
				Entry:             directoryEntry,
				ValidationResult_: pspsignanalysis.Validation_Correct,
			})
		}
	}
	return result, nil
}

func (analyzer *PSPSignature) validateBIOSDirectoryEntries(
	ctx context.Context,
	amdFw *amd_manifest.AMDFirmware,
	keyDB psb.KeySet,
	level uint,
	biosEntries []uint32,
) ([]*pspsignanalysis.ValidatedItem, error) {
	log := logger.FromCtx(ctx)
	thriftBIOSDirectory, err := conv.ThriftBIOSDirectoryOfLevel(level)
	if err != nil {
		return nil, err
	}
	biosDirectory, err := psb.GetBIOSDirectoryOfLevel(level)
	if err != nil {
		return nil, err
	}

	var result []*pspsignanalysis.ValidatedItem
	for _, checkedEntry := range biosEntries {
		biosDirectoryEntry := amd_manifest.BIOSDirectoryTableEntryType(checkedEntry)

		addEntryError := func(directoryEntry *psptypes.DirectoryEntry, entryErr error) error {
			item, convErr := errorToValidatedItem(thriftBIOSDirectory, directoryEntry, entryErr)
			if convErr != nil {
				log.Errorf("Failed to get validated item info for %v", convErr)
				return convErr
			}
			result = append(result, item)
			return nil
		}

		biosEntries, err := psb.GetBIOSEntries(amdFw.PSPFirmware(), level, biosDirectoryEntry)
		if err != nil {
			log.Errorf("Failed to get BIOS entries '%s' of directory '%s'", biosDirectoryEntry, biosDirectory)
			return nil, err
		}

		for _, biosEntry := range biosEntries {
			directoryEntry := &psptypes.DirectoryEntry{
				BIOSEntry: &psptypes.BIOSDirectoryEntry{
					Entry:    conv.ToThriftBIOSDirectoryTableEntryType(biosDirectoryEntry),
					Instance: int16(biosEntry.Instance),
				},
			}

			validationResult, validationErr := psb.ValidatePSPEntry(amdFw, keyDB, biosEntry.SourceAddress, uint64(biosEntry.Size))
			if validationErr != nil {
				if err := addEntryError(directoryEntry, validationErr); err != nil {
					return nil, err
				}
				continue
			}

			if validationResult.Error() != nil {
				if err := addEntryError(directoryEntry, validationResult.Error()); err != nil {
					return nil, err
				}
			} else {
				result = append(result, &pspsignanalysis.ValidatedItem{
					Directory:         thriftBIOSDirectory,
					Entry:             directoryEntry,
					ValidationResult_: pspsignanalysis.Validation_Correct,
				})
			}
		}
	}
	return result, nil
}

func errorToValidatedItem(directory psptypes.DirectoryType, entry *psptypes.DirectoryEntry, inErr error) (*pspsignanalysis.ValidatedItem, error) {
	var errNotFound psb.ErrNotFound
	if errors.As(inErr, &errNotFound) {
		return newValidatedItem(directory, entry, errNotFound.GetItem(), pspsignanalysis.Validation_NotFound, errNotFound.Error())
	}

	var errInvalidFormat psb.ErrInvalidFormat
	if errors.As(inErr, &errInvalidFormat) {
		return newValidatedItem(directory, entry, errInvalidFormat.GetItem(), pspsignanalysis.Validation_InvalidFormat, errNotFound.Error())
	}

	validationResult := pspsignanalysis.Validation_Unknown
	var (
		signatureCheckErr *psb.SignatureCheckError
		unknownKeyErr     *psb.UnknownSigningKeyError
	)
	switch {
	case errors.As(inErr, &signatureCheckErr):
		validationResult = pspsignanalysis.Validation_IncorrectSignature
	case errors.As(inErr, &unknownKeyErr):
		validationResult = pspsignanalysis.Validation_KeyNotFound
	}
	return &pspsignanalysis.ValidatedItem{
		Directory:             directory,
		Entry:                 entry,
		ValidationResult_:     validationResult,
		ValidationDescription: inErr.Error(),
	}, nil
}

func newValidatedItem(
	parentItemDirectory psptypes.DirectoryType,
	parentItemEntry *psptypes.DirectoryEntry,
	input psb.FirmwareItem,
	validationResult pspsignanalysis.Validation,
	validationDescription string,
) (*pspsignanalysis.ValidatedItem, error) {
	if input == nil {
		return &pspsignanalysis.ValidatedItem{
			Directory:             parentItemDirectory,
			Entry:                 parentItemEntry,
			ValidationResult_:     validationResult,
			ValidationDescription: validationDescription,
		}, nil
	}

	switch item := input.(type) {
	case psb.DirectoryType:
		directoryType, err := conv.ToThriftDirectoryType(item)
		if err != nil {
			return nil, err
		}
		return &pspsignanalysis.ValidatedItem{
			Directory:             directoryType,
			ValidationResult_:     validationResult,
			ValidationDescription: validationDescription,
		}, nil
	case psb.BIOSDirectoryEntryItem:
		directoryType, err := conv.ThriftBIOSDirectoryOfLevel(uint(item.Level))
		if err != nil {
			return nil, err
		}
		return &pspsignanalysis.ValidatedItem{
			Directory: directoryType,
			Entry: &psptypes.DirectoryEntry{
				BIOSEntry: &psptypes.BIOSDirectoryEntry{
					Entry:    conv.ToThriftBIOSDirectoryTableEntryType(item.Entry),
					Instance: int16(item.Instance),
				},
			},
			ValidationResult_:     validationResult,
			ValidationDescription: validationDescription,
		}, nil
	case psb.PSPDirectoryEntryItem:
		directoryType, err := conv.ThriftPSPDirectoryOfLevel(uint(item.Level))
		if err != nil {
			return nil, err
		}
		entryType := conv.ToThriftPSPDirectoryTableEntryType(item.Entry)
		return &pspsignanalysis.ValidatedItem{
			Directory: directoryType,
			Entry: &psptypes.DirectoryEntry{
				PSPEntry: &entryType,
			},
			ValidationResult_:     validationResult,
			ValidationDescription: validationDescription,
		}, nil
	}
	return nil, fmt.Errorf("unknown firmware item type: '%T', value: '%v'", input, input)
}

func validatedItemsIssues(items []*pspsignanalysis.ValidatedItem) []analysis.Issue {
	var result []analysis.Issue
	for _, item := range items {
		if item == nil || item.GetValidationResult_() == pspsignanalysis.Validation_Correct {
			continue
		}

		var issueDescription string
		switch item.GetValidationResult_() {
		case pspsignanalysis.Validation_InvalidFormat:
			issueDescription = fmt.Sprintf("%s has invalid format", pspItemName(item.Directory, item.Entry))
		case pspsignanalysis.Validation_NotFound:
			issueDescription = fmt.Sprintf("%s was not found", pspItemName(item.Directory, item.Entry))
		case pspsignanalysis.Validation_IncorrectSignature:
			issueDescription = fmt.Sprintf("%s has incorrect signature", pspItemName(item.Directory, item.Entry))
		case pspsignanalysis.Validation_KeyNotFound:
			issueDescription = fmt.Sprintf("%s signature key was not found", pspItemName(item.Directory, item.Entry))
		}

		if len(item.GetValidationDescription()) > 0 {
			issueDescription += ": " + item.GetValidationDescription()
		}
		result = append(result, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: issueDescription,
		})
	}
	return result
}

func pspItemName(directory psptypes.DirectoryType, entry *psptypes.DirectoryEntry) string {
	if entry != nil {
		switch {
		case entry.IsSetPSPEntry():
			return fmt.Sprintf("PSP item %d of %s", entry.PSPEntry, directory)
		case entry.IsSetBIOSEntry():
			return fmt.Sprintf("BIOS item %d instance: %d of %s", entry.BIOSEntry.Entry, entry.BIOSEntry.Instance, directory)
		}
	}
	return directory.String()
}

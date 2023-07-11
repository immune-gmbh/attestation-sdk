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
package amd

import (
	"bytes"
	"context"
	"fmt"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
	"github.com/linuxboot/fiano/pkg/amd/psb"

	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/types"
	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/validator"
)

// PSPSignatureCorruption is a configurable TestCase for corrupting AMD PSP firmware
type PSPSignatureCorruption struct {
	table          psb.DirectoryType
	recoveryTable  *psb.DirectoryType
	entryID        uint32
	skipIfNotFound bool

	validators validator.Validators
}

// Setup implements types.TestCase
func (tc PSPSignatureCorruption) Setup(ctx context.Context, image []byte) error {
	fw, err := psb.ParseAMDFirmware(image)
	if err != nil {
		return err
	}

	mainEntries, err := psb.GetEntries(fw.PSPFirmware(), tc.table, tc.entryID)
	if err != nil {
		return err
	}
	if len(mainEntries) == 0 {
		return fmt.Errorf("found no entries to corrupt")
	}

	corruptImage := func(offset, length uint64) error {
		if offset+length > uint64(len(image)) {
			return fmt.Errorf("invalid entry with location='%d' offset='%d' is out of image's bound", offset, length)
		}

		pspHeader, err := amd_manifest.ParsePSPHeader(bytes.NewReader(image[offset : offset+length]))
		if err != nil {
			return fmt.Errorf("failed to parse psp header: %w", err)
		}
		corruptedVersionOffset := offset + pspHeader.VersionOffset()
		image[corruptedVersionOffset] = image[corruptedVersionOffset] + 1
		return nil
	}

	if tc.recoveryTable != nil {
		recoveryEntries, err := psb.GetEntries(fw.PSPFirmware(), *tc.recoveryTable, tc.entryID)
		if err != nil {
			return err
		}
		for _, entry := range recoveryEntries {
			if err := corruptImage(entry.Offset, entry.Length); err != nil {
				return fmt.Errorf("failed to corrupt recovery image: %w", err)
			}
		}
	}

	// The easiest thing to corrupt is version since it is not forced to be checked on AMD Milan
	for _, entry := range mainEntries {
		if err := corruptImage(entry.Offset, entry.Length); err != nil {
			return fmt.Errorf("failed to corrupt image: %w", err)
		}
	}
	return nil
}

// Matches implements types.TestCase
func (tc PSPSignatureCorruption) Matches(fwInfo types.FirmwareInfoProvider) bool {

	isAmdPsb, err := types.SupportsFeature(fwInfo, types.AmdPSBMilan)
	if err != nil {
		panic(fmt.Sprintf("cannot determine the architecture: %v", err))
	}

	if !isAmdPsb {
		return false
	}

	amdFw, err := fwInfo.PSPFirmware()
	if err != nil {
		return false
	}

	pspFw := amdFw.PSPFirmware()
	if pspFw == nil {
		return false
	}

	entries, _ := psb.GetEntries(pspFw, tc.table, tc.entryID)
	if len(entries) == 0 {
		return tc.skipIfNotFound
	}
	return true
}

// Validate implements types.TestCase
func (tc PSPSignatureCorruption) Validate(ctx context.Context, origImage []byte, opts ...types.Option) error {
	return nil
}

// Severity implements types.TestCase
func (tc PSPSignatureCorruption) Severity() types.Severity {
	return types.SeverityBlocker
}

// NewPSPSignatureCorruption creates a new PSPSignatureCorruption test case that corrupts a single item in given PSP table
func NewPSPSignatureCorruption(table psb.DirectoryType, entryID uint32, skipIfNotFound bool, extraValidators ...validator.Validator,
) PSPSignatureCorruption {
	return PSPSignatureCorruption{
		table:          table,
		entryID:        entryID,
		skipIfNotFound: skipIfNotFound,
		validators:     validator.CommonHostBootUpNotExpected(extraValidators...),
	}
}

// NewPSPSignatureCorruptionWithRecovery creates a new PSPSignatureCorruption test case that corrupts a single item in given PSP table and
// all entries of that type in recovery table
func NewPSPSignatureCorruptionWithRecovery(table, recoveryTable psb.DirectoryType, entryID uint32,
	skipIfNotFound bool, extraValidators ...validator.Validator,
) PSPSignatureCorruption {
	return PSPSignatureCorruption{
		table:          table,
		recoveryTable:  &recoveryTable,
		entryID:        entryID,
		skipIfNotFound: skipIfNotFound,
		validators:     validator.CommonHostBootUpNotExpected(extraValidators...),
	}
}

// ModifiedPSPBootLoader represents a testcase with modified PSB bootloader
type ModifiedPSPBootLoader struct {
	PSPSignatureCorruption
}

// NewModifiedPSPBootLoader creates a modified PSB bootloader testcase
func NewModifiedPSPBootLoader() ModifiedPSPBootLoader {
	return ModifiedPSPBootLoader{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(amd_manifest.PSPBootloaderFirmwareEntry), false, NewPSPSignatureVerificationFailedSELValidator(),
		),
	}
}

var _ types.TestCase = NewModifiedPSPBootLoader()

// ModifiedABLPublicKey represents a testcase with modified ABL key
type ModifiedABLPublicKey struct {
	PSPSignatureCorruption
}

// NewModifiedABLPublicKey creates a modified PSB bootloader testcase
func NewModifiedABLPublicKey() ModifiedABLPublicKey {
	return ModifiedABLPublicKey{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.ABLPublicKey), false, validator.MustExpectSEL(
				".*OEM BIOS Signing Key failed signature verification Assertion.*",
				".*PSB_STS.*PSB Pass Assertion.*",
			),
		),
	}
}

var _ types.TestCase = NewModifiedABLPublicKey()

// ModifiedSMUOffchipFirmware represents a testcase with modified SMU offchip firmware
type ModifiedSMUOffchipFirmware struct {
	PSPSignatureCorruption
}

// NewModifiedSMUOffchipFirmware creates a modified PSB bootloader testcase
func NewModifiedSMUOffchipFirmware() ModifiedSMUOffchipFirmware {
	return ModifiedSMUOffchipFirmware{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.SMUOffChipFirmwareEntry), true, /*NewPSPSignatatureVerificationFailedSELValidator(), - minor bug in AMD firmware?*/
		),
	}
}

var _ types.TestCase = NewModifiedSMUOffchipFirmware()

// ModifiedUnlockDebugImage represents a testcase with modified unlock debug image
type ModifiedUnlockDebugImage struct {
	PSPSignatureCorruption
}

// NewModifiedUnlockDebugImage creates a modified PSB bootloader testcase
func NewModifiedUnlockDebugImage() ModifiedUnlockDebugImage {
	return ModifiedUnlockDebugImage{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.UnlockDebugImageEntry), true, /*NewPSPSignatureVerificationFailedSELValidator(), - minor bug in AMD firmware?*/
		),
	}
}

var _ types.TestCase = NewModifiedUnlockDebugImage()

// ModifiedSecurityPolicyBinary represents a testcase with modified Security Policy binary
type ModifiedSecurityPolicyBinary struct {
	PSPSignatureCorruption
}

// NewModifiedSecurityPolicyBinary creates modified Security Policy Binary testcase
func NewModifiedSecurityPolicyBinary() ModifiedSecurityPolicyBinary {
	return ModifiedSecurityPolicyBinary{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.SecurityPolicyBinaryEntry), true, /*NewPSPSignatureVerificationFailedSELValidator(), - minor bug in AMD firmware?*/
		),
	}
}

var _ types.TestCase = NewModifiedSecurityPolicyBinary()

// ModifiedMP5Firmware represents a testcase with modifided MP5 Firmware
type ModifiedMP5Firmware struct {
	PSPSignatureCorruption
}

// NewModifiedMP5Firmware creates modified MP5 firmware testcase
func NewModifiedMP5Firmware() ModifiedMP5Firmware {
	return ModifiedMP5Firmware{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.MP5FirmwareEntry), true, /*NewPSPSignatureVerificationFailedSELValidator(), - minor bug in AMD firmware?*/
		),
	}
}

var _ types.TestCase = NewModifiedMP5Firmware()

// ModifiedPSPAGESABinary0 represents a testcase with modified AGESA Binary 0
type ModifiedPSPAGESABinary0 struct {
	PSPSignatureCorruption
}

// NewModifiedPSPAGESABinary0 creates modified AGESA Binary 0 testcase
func NewModifiedPSPAGESABinary0() ModifiedPSPAGESABinary0 {
	return ModifiedPSPAGESABinary0{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.AGESABinary0Entry), false, /*NewPSPSignatureVerificationFailedSELValidator(), - minor bug in AMD firmware?*/
		),
	}
}

var _ types.TestCase = NewModifiedPSPAGESABinary0()

// ModifiedSEVCode represents a testcase with modified SEV Code
type ModifiedSEVCode struct {
	PSPSignatureCorruption
}

// NewModifiedSEVCode creates modified SEV Code testcase (Currently generates "PSB_STS (0x46), Event Data: (EE00FF) PSB Pass Assertion")
func NewModifiedSEVCode() ModifiedSEVCode {
	return ModifiedSEVCode{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.SEVCodeEntry), true, /*NewPSPSignatatureVerificationFailedSELValidator(), - minor bug in AMD firmware?*/
		),
	}
}

var _ types.TestCase = NewModifiedSEVCode()

// ModifiedDXIOPHYSRAMFirmware represents a testcase with modified DXIO SRAM firmware
type ModifiedDXIOPHYSRAMFirmware struct {
	PSPSignatureCorruption
}

// NewModifiedDXIOPHYSRAMFirmware creates modified DXIO SRAM firmware
func NewModifiedDXIOPHYSRAMFirmware() ModifiedDXIOPHYSRAMFirmware {
	return ModifiedDXIOPHYSRAMFirmware{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.DXIOPHYSRAMFirmwareEntry), true, NewPSPSignatureVerificationFailedSELValidator(),
		),
	}
}

var _ types.TestCase = NewModifiedDXIOPHYSRAMFirmware()

// ModifiedDRTMTA represents a testcase with modified DRTM TA (Currently generates "PSB_STS (0x46), Event Data: (EE00FF) PSB Pass Assertion")
type ModifiedDRTMTA struct {
	PSPSignatureCorruption
}

// NewModifiedDRTMTA creates modified DRTM TA SRAM firmware testcase
func NewModifiedDRTMTA() ModifiedDRTMTA {
	return ModifiedDRTMTA{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.DRTMTAEntry), true, NewPSPSignatureVerificationFailedSELValidator(),
		),
	}
}

var _ types.TestCase = NewModifiedDRTMTA()

// ModifiedKeyDatabase represents a testcase with modified key database
type ModifiedKeyDatabase struct {
	PSPSignatureCorruption
}

// NewModifiedKeyDatabase creates modified Key database testcase
func NewModifiedKeyDatabase() ModifiedKeyDatabase {
	return ModifiedKeyDatabase{
		NewPSPSignatureCorruptionWithRecovery(psb.PSPDirectoryLevel2, psb.PSPDirectoryLevel1,
			uint32(psb.KeyDatabaseEntry), false, /*NewPSPSignatureVerificationFailedSELValidator(), - minor bug in AMD firmware?*/
		),
	}
}

var _ types.TestCase = NewModifiedKeyDatabase()

// ModifiedPMUFirmwareInstructions represents a testcase with modified PMU firmware instructions
type ModifiedPMUFirmwareInstructions struct {
	PSPSignatureCorruption
}

// NewModifiedPMUFirmwareInstructions creates modified PMU firmware instructions test case
func NewModifiedPMUFirmwareInstructions() ModifiedPMUFirmwareInstructions {
	return ModifiedPMUFirmwareInstructions{
		NewPSPSignatureCorruptionWithRecovery(psb.BIOSDirectoryLevel2, psb.BIOSDirectoryLevel1,
			uint32(amd_manifest.PMUFirmwareInstructionsEntry), true, NewPSPSignatureVerificationFailedSELValidator(),
		),
	}
}

var _ types.TestCase = NewModifiedPMUFirmwareInstructions()

// ModifiedPMUFirmwareData represents a testcase with modified PMU firmware data
type ModifiedPMUFirmwareData struct {
	PSPSignatureCorruption
}

// NewModifiedPMUFirmwareData creates modified PMU firmware data test case
func NewModifiedPMUFirmwareData() ModifiedPMUFirmwareData {
	return ModifiedPMUFirmwareData{
		NewPSPSignatureCorruptionWithRecovery(psb.BIOSDirectoryLevel2, psb.BIOSDirectoryLevel1,
			uint32(amd_manifest.PMUFirmwareDataEntry), true, NewPSPSignatureVerificationFailedSELValidator(),
		),
	}
}

var _ types.TestCase = NewModifiedPMUFirmwareData()

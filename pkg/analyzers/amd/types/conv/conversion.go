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

package conv

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/types/generated/psptypes"
	"github.com/linuxboot/fiano/pkg/amd/psb"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// ToThriftDirectoryType converts from psb.DirectoryType to psptypes.DirectoryType
func ToThriftDirectoryType(directoryType psb.DirectoryType) (psptypes.DirectoryType, error) {
	switch directoryType {
	case psb.BIOSDirectoryLevel1:
		return psptypes.DirectoryType_BIOSTableLevel1, nil
	case psb.BIOSDirectoryLevel2:
		return psptypes.DirectoryType_BIOSTableLevel2, nil
	case psb.PSPDirectoryLevel1:
		return psptypes.DirectoryType_PSPTableLevel1, nil
	case psb.PSPDirectoryLevel2:
		return psptypes.DirectoryType_PSPTableLevel2, nil
	}
	return 0, fmt.Errorf("unknown directory type: '%s'", directoryType)
}

// FromThriftDirectoryType converts from psptypes.DirectoryType to psb.DirectoryType
func FromThriftDirectoryType(directoryType psptypes.DirectoryType) (psb.DirectoryType, error) {
	switch directoryType {
	case psptypes.DirectoryType_BIOSTableLevel1:
		return psb.BIOSDirectoryLevel1, nil
	case psptypes.DirectoryType_BIOSTableLevel2:
		return psb.BIOSDirectoryLevel2, nil
	case psptypes.DirectoryType_PSPTableLevel1:
		return psb.PSPDirectoryLevel1, nil
	case psptypes.DirectoryType_PSPTableLevel2:
		return psb.PSPDirectoryLevel2, nil
	}
	return 0, fmt.Errorf("unknown directory type: '%s'", directoryType)
}

// ThriftBIOSDirectoryOfLevel returns a BIOS psptypes.DirectoryType for a given level
func ThriftBIOSDirectoryOfLevel(level uint) (psptypes.DirectoryType, error) {
	switch level {
	case 1:
		return psptypes.DirectoryType_BIOSTableLevel1, nil
	case 2:
		return psptypes.DirectoryType_BIOSTableLevel2, nil
	}
	return 0, fmt.Errorf("invalid BIOS directory level: %d", level)
}

// ThriftPSPDirectoryOfLevel returns a PSP psptypes.DirectoryType for a given level
func ThriftPSPDirectoryOfLevel(level uint) (psptypes.DirectoryType, error) {
	switch level {
	case 1:
		return psptypes.DirectoryType_PSPTableLevel1, nil
	case 2:
		return psptypes.DirectoryType_PSPTableLevel2, nil
	}
	return 0, fmt.Errorf("invalid PSP directory level: %d", level)
}

// ToThriftPSPDirectoryTableEntryType converts from amd_manifest.PSPDirectoryTableEntry to psptypes.PSPDirectoryTableEntry
func ToThriftPSPDirectoryTableEntryType(pspEntryType amd_manifest.PSPDirectoryTableEntryType) psptypes.PSPDirectoryTableEntryType {
	return psptypes.PSPDirectoryTableEntryType(pspEntryType)
}

// FromThriftPSPDirectoryTableEntryType converts from psptypes.PSPDirectoryTableEntry to amd_manifest.PSPDirectoryTableEntry
func FromThriftPSPDirectoryTableEntryType(pspEntryType psptypes.PSPDirectoryTableEntryType) amd_manifest.PSPDirectoryTableEntryType {
	return amd_manifest.PSPDirectoryTableEntryType(pspEntryType)
}

// ToThriftBIOSDirectoryTableEntryType converts from amd_manifest.BIOSDirectoryTableEntryType to psptypes.BIOSDirectoryTableEntryType
func ToThriftBIOSDirectoryTableEntryType(biosEntryType amd_manifest.BIOSDirectoryTableEntryType) psptypes.BIOSDirectoryTableEntryType {
	return psptypes.BIOSDirectoryTableEntryType(biosEntryType)
}

// FromThriftBIOSDirectoryTableEntryType converts from psptypes.BIOSDirectoryTableEntryType to amd_manifest.BIOSDirectoryTableEntryType
func FromThriftBIOSDirectoryTableEntryType(biosEntryType psptypes.BIOSDirectoryTableEntryType) amd_manifest.BIOSDirectoryTableEntryType {
	return amd_manifest.BIOSDirectoryTableEntryType(biosEntryType)
}

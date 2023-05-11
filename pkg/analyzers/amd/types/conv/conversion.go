package conv

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/types/psptypes"
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

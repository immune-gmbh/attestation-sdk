package conv

import (
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/types/generated/psptypes"
	"github.com/linuxboot/fiano/pkg/amd/psb"

	"github.com/stretchr/testify/require"
)

func TestDirectoryType(t *testing.T) {
	for _, directory := range psb.AllDirectoryTypes() {
		thriftDirectory, err := ToThriftDirectoryType(directory)
		require.NoError(t, err)

		resultDirectory, err := FromThriftDirectoryType(thriftDirectory)
		require.NoError(t, err)

		require.Equal(t, directory, resultDirectory)
	}
}

func TestThriftBIOSDirectoryOfLevel(t *testing.T) {
	biosDirLevel1, err := ThriftBIOSDirectoryOfLevel(1)
	require.NoError(t, err)
	require.Equal(t, psptypes.DirectoryType_BIOSTableLevel1, biosDirLevel1)

	biosDirLevel2, err := ThriftBIOSDirectoryOfLevel(2)
	require.NoError(t, err)
	require.Equal(t, psptypes.DirectoryType_BIOSTableLevel2, biosDirLevel2)

	_, err = ThriftBIOSDirectoryOfLevel(3)
	require.Error(t, err)
}

func TestThriftPDPDirectoryOfLevel(t *testing.T) {
	pspDirLevel1, err := ThriftPSPDirectoryOfLevel(1)
	require.NoError(t, err)
	require.Equal(t, psptypes.DirectoryType_PSPTableLevel1, pspDirLevel1)

	pspDirLevel2, err := ThriftPSPDirectoryOfLevel(2)
	require.NoError(t, err)
	require.Equal(t, psptypes.DirectoryType_PSPTableLevel2, pspDirLevel2)

	_, err = ThriftPSPDirectoryOfLevel(3)
	require.Error(t, err)
}

func TestPSPDirectoryTableEntryType(t *testing.T) {
	for _, pspThriftEntryType := range psptypes.PSPDirectoryTableEntryTypeValues {
		pspEntryType := FromThriftPSPDirectoryTableEntryType(pspThriftEntryType)
		require.Equal(t, pspThriftEntryType, ToThriftPSPDirectoryTableEntryType(pspEntryType))
	}
}

func TestBIOSDirectoryTableEntryType(t *testing.T) {
	for _, biosThriftEntryType := range psptypes.BIOSDirectoryTableEntryTypeValues {
		biosEntryType := FromThriftBIOSDirectoryTableEntryType(biosThriftEntryType)
		require.Equal(t, biosThriftEntryType, ToThriftBIOSDirectoryTableEntryType(biosEntryType))
	}
}

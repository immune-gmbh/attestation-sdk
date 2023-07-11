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
	"testing"

	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/amd/types/generated/psptypes"
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
	for pspThriftEntryType := psptypes.PSPDirectoryTableEntryType(0); ; pspThriftEntryType++ {
		if _, err := psptypes.PSPDirectoryTableEntryTypeFromString(pspThriftEntryType.String()); err != nil {
			// reach the end of available values of PSPDirectoryTableEntryType
			break
		}
		pspEntryType := FromThriftPSPDirectoryTableEntryType(pspThriftEntryType)
		require.Equal(t, pspThriftEntryType, ToThriftPSPDirectoryTableEntryType(pspEntryType))
	}
}

func TestBIOSDirectoryTableEntryType(t *testing.T) {
	for biosThriftEntryType := psptypes.BIOSDirectoryTableEntryType(0); ; biosThriftEntryType++ {
		if _, err := psptypes.BIOSDirectoryTableEntryTypeFromString(biosThriftEntryType.String()); err != nil {
			// reach the end of available values of BIOSDirectoryTableEntryType
			break
		}
		biosEntryType := FromThriftBIOSDirectoryTableEntryType(biosThriftEntryType)
		require.Equal(t, biosThriftEntryType, ToThriftBIOSDirectoryTableEntryType(biosEntryType))
	}
}

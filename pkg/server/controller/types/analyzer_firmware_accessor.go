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
package types

import (
	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/dmidecode"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"
	"github.com/immune-gmbh/attestation-sdk/pkg/uefi"
)

func init() {
	analysis.RegisterType((*AnalyzerFirmwareAccessor)(nil))
}

// AnalyzerFirmwareAccessor implements analysis.Blob, but it is
// serialized with the ImageID instead of the image content.
type AnalyzerFirmwareAccessor struct {
	// == Non-serializable part ==

	image []byte
	// if we already parsed the firmware, we can avoid second parsing in analyzers, thus:
	parsedCache   *uefi.UEFI
	biosInfoCache *dmidecode.BIOSInfo

	// == Serializable part ==

	ImageID types.ImageID
}

var _ analysis.Blob = (*AnalyzerFirmwareAccessor)(nil)

// Bytes implements analysis.Blob
func (fw *AnalyzerFirmwareAccessor) Bytes() []byte {
	if fw.image == nil {
		panic("method Bytes() is not available because the accessor was not initialized, yet (fix: call Init() first)")
	}
	return fw.image
}

// Init initializes the FirmwareAccessor after it was deserialized.
//
// Argument `image` is required to correspond the image with
// ID equals to `fw.ImageID`. This correspondance is not checked,
// so it is the responsibility of the caller to make sure this
// requirement is satisfied.
//
// Arguments `parsedCache` and `biosInfoCache` are optional and may
// be provided to avoid reparsing the UEFI layout and extraction of
// BIOSInfo.
func (fw *AnalyzerFirmwareAccessor) Init(
	image []byte,
	parsedCache *uefi.UEFI,
	biosInfoCache *dmidecode.BIOSInfo,
) {
	fw.image = image
	fw.parsedCache = parsedCache
	fw.biosInfoCache = biosInfoCache
}

var _ biosInfoCacheInterface = (*AnalyzerFirmwareAccessor)(nil)

// BIOSInfoCache implements biosInfoCacheInterface
func (fw *AnalyzerFirmwareAccessor) BIOSInfoCache() *dmidecode.BIOSInfo {
	return fw.biosInfoCache
}

var _ parsedFirmwareCacheInterface = (*AnalyzerFirmwareAccessor)(nil)

// ParsedCache implements parsedFirmwareCacheInterface
func (fw *AnalyzerFirmwareAccessor) ParsedCache() *uefi.UEFI {
	return fw.parsedCache
}

package types

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/dmidecode"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/uefi"
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

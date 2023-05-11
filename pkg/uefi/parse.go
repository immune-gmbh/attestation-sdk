package uefi

import (
	"sync"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"
)

// UEFI is just an alias for the upstream type uefi.UEFI
type UEFI = uefi.UEFI

// fianoUEFI.DisableDecompression is a global setting, so we use this locker
// to access it safely

var fianoUEFIConfigMutex = sync.RWMutex{}

// Parse takes a set of bytes representing a UEFI image and parses it into a
// PCR0-measurements-aware set of components. This can be used for e.g.
// reading the DMI table from an image file.
func Parse(imageBytes []byte, decompress bool) (*UEFI, error) {
	fianoUEFIConfigMutex.RLock()
	defer fianoUEFIConfigMutex.RUnlock()
	expectedDisableDecompressionValue := !decompress
	for fianoUEFI.DisableDecompression != expectedDisableDecompressionValue {
		fianoUEFIConfigMutex.RUnlock()
		fianoUEFIConfigMutex.Lock()
		fianoUEFI.DisableDecompression = expectedDisableDecompressionValue
		fianoUEFIConfigMutex.Unlock()
		fianoUEFIConfigMutex.RLock()
	}

	return uefi.ParseUEFIFirmwareBytes(imageBytes)
}

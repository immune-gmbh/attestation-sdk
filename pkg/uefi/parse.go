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

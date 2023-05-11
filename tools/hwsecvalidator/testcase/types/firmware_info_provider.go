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
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// FirmwareInfoProvider is an easy access to common information about firmware
type FirmwareInfoProvider interface {
	Firmware() *uefi.UEFI
	PSPFirmware() (*amd_manifest.AMDFirmware, error)
}

type firmwareInfoProvider struct {
	firmware    *uefi.UEFI
	pspFirmware *amd_manifest.AMDFirmware
}

func (p *firmwareInfoProvider) Firmware() *uefi.UEFI {
	return p.firmware
}

func (p *firmwareInfoProvider) PSPFirmware() (*amd_manifest.AMDFirmware, error) {
	if p.pspFirmware != nil {
		return p.pspFirmware, nil
	}

	var err error
	p.pspFirmware, err = amd_manifest.NewAMDFirmware(p.firmware)
	return p.pspFirmware, err
}

// NewFirmwareInfoProvider creates a new FirmwareInfoProvider object
func NewFirmwareInfoProvider(image []byte) (FirmwareInfoProvider, error) {
	fw, err := uefi.ParseUEFIFirmwareBytes(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse firmware as UEFI image: %w", err)
	}
	return &firmwareInfoProvider{
		firmware: fw,
	}, nil
}

// NewFirmwareInfoProviderFromUEFI creates a new FirmwareInfoProvider from a parsed UEFI firmware object
func NewFirmwareInfoProviderFromUEFI(fw *uefi.UEFI) (FirmwareInfoProvider, error) {
	return &firmwareInfoProvider{
		firmware: fw,
	}, nil
}

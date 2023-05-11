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

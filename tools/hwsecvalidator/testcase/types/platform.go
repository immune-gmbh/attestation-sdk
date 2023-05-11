package types

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/klauspost/cpuid/v2"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

// SecurityFeature represents a generic security feature supported by the platform
type SecurityFeature int

const (
	// AmdPSBMilan represents Platform Secure Boot for AMD Milan architecture
	AmdPSBMilan SecurityFeature = 0

	// IntelCBnT represents Intel Converged BootGuard for Intel architecture
	IntelCBnT = 1

	// IntelTXT represents legacy IntelTXT architecture
	IntelTXT = 2

	// <REMOVED>

	// UEFIMeasurements represents support for UEFI firmware which extends measurements into TPM
	UEFIMeasurements = 4
)

// String returns a string representation of the security feature
func (f SecurityFeature) String() string {
	switch f {
	case AmdPSBMilan:
		return "AMD_PSB_MILAN"
	case IntelCBnT:
		return "INTEL_CBNT"
	case IntelTXT:
		return "INTEL_TXT"
	case UEFIMeasurements:
		return "UEFI_MEASUREMENTS"
	}
	return "UNKNOWN"
}

// SecurityFeatureCheck verifies if a security feature is supported
type SecurityFeatureCheck func(p FirmwareInfoProvider) bool

// AmdPSBMilanCheck verifies if the Platform supports AMD PSB for Milan architecture
func AmdPSBMilanCheck(p FirmwareInfoProvider) bool {
	return pcr.IsAMDPSPFirmware(context.Background(), p.Firmware())
}

// IntelCBnTCheck verifies if the Platform supports Intel CBnT
func IntelCBnTCheck(p FirmwareInfoProvider) bool {
	return pcr.IsCBnTFirmware(p.Firmware())
}

// IntelTXTCheck verifies if the Platform supports Intel TXT
func IntelTXTCheck(p FirmwareInfoProvider) bool {
	if _, err := fit.GetEntries(p.Firmware().ImageBytes()); err == nil {
		return true
	}
	return false
}

// UEFIMeasurementsCheck verifies if the Platform supports measurements for UEFI.
func UEFIMeasurementsCheck(p FirmwareInfoProvider) bool {
	// We expect all UEFI firmware to support measurements
	return p.Firmware() != nil
}

// SecurityFeatureChecks collects all the supported checks to determine if a platform supports
// a specific security feature
var SecurityFeatureChecks = map[SecurityFeature]SecurityFeatureCheck{
	AmdPSBMilan:      AmdPSBMilanCheck,
	IntelCBnT:        IntelCBnTCheck,
	IntelTXT:         IntelTXTCheck,
	UEFIMeasurements: UEFIMeasurementsCheck,
}

// Architectures is a map which associates CPU architectures to corresponding security feature checks.
// The architecture is identifier even if only one feature is supported
var Architectures = map[cpuid.Vendor][]SecurityFeature{
	cpuid.Intel: {IntelCBnT, IntelTXT},
	cpuid.AMD:   {AmdPSBMilan},
}

// SupportsFeature determines if the platform supports a specific security feature
func SupportsFeature(p FirmwareInfoProvider, f SecurityFeature) (bool, error) {
	check, ok := SecurityFeatureChecks[f]
	if !ok {
		return false, fmt.Errorf("check for %s not supported", f)
	}
	return check(p), nil
}

// IsArchitecture determines the architecture based on the known security features
func IsArchitecture(p FirmwareInfoProvider, v cpuid.Vendor) (bool, error) {
	features, ok := Architectures[v]
	if !ok {
		return false, fmt.Errorf("architecture %s not supported", v)
	}

	for _, feature := range features {
		check, ok := SecurityFeatureChecks[feature]
		if !ok {
			return false, fmt.Errorf("architecture %s can be checked with feature %s, but no checks for that feature are available", v, feature)
		}
		if check(p) {
			return true, nil
		}
	}
	return false, nil
}

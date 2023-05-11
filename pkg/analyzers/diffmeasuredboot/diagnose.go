package diffmeasuredboot

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/generated/diffanalysis"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/uefi"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/steakknife/hamming"
)

// Diagnose provides the diagnosis how to interpret an image corruption.
func Diagnose(
	log logger.Logger,
	diffRanges pkgbytes.Ranges,
	origImage *uefi.UEFI,
	modifiedImage analysis.ActualFirmwareBlob,
	actualBIOSInfo *analysis.ActualBIOSInfo,
	origBIOSInfo *analysis.OriginalBIOSInfo,
) diffanalysis.DiffDiagnosis {
	if len(origImage.Buf()) != len(modifiedImage.Bytes()) {
		panic(fmt.Sprintf("images has different size: %d != %d", len(origImage.Buf()), len(modifiedImage.Bytes())))
	}

	modifiedBytes := diffRanges.Compile(modifiedImage.Bytes())
	if len(modifiedBytes) == 0 {
		return diffanalysis.DiffDiagnosis_Match
	}

	origBytes := diffRanges.Compile(origImage.Buf())

	if len(modifiedBytes) == 1 {
		// damages we see just happening in our fleet

		if hamming.Byte(origBytes[0], modifiedBytes[0]) == 1 {
			// a bitflip
			return diffanalysis.DiffDiagnosis_UnsuspiciousDamage
		}

		if modifiedBytes[0] == 0xff {
			// a whole byte turned to 0xff
			return diffanalysis.DiffDiagnosis_UnsuspiciousDamage
		}
	}

	switch {
	case actualBIOSInfo == nil:
		log.Debugf("no actual BIOS info, assuming BIOS version match")
	case origBIOSInfo == nil:
		return diffanalysis.DiffDiagnosis_InvalidOriginalFirmware
	default:
		if origBIOSInfo.BIOSInfo != actualBIOSInfo.BIOSInfo {
			return diffanalysis.DiffDiagnosis_FirmwareVersionMismatch
		}
	}

	return diffanalysis.DiffDiagnosis_SuspiciousDamage
}

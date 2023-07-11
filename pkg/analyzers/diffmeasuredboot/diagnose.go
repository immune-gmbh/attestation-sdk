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

package diffmeasuredboot

import (
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/analyzers/diffmeasuredboot/report/generated/diffanalysis"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/immune-gmbh/attestation-sdk/pkg/uefi"
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

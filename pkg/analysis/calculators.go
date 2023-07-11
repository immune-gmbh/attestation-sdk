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

package analysis

import (
	"bytes"
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"

	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"

	"github.com/immune-gmbh/attestation-sdk/pkg/dmidecode"
	"github.com/immune-gmbh/attestation-sdk/pkg/imgalign"
	"github.com/immune-gmbh/attestation-sdk/pkg/measurements"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"
	"github.com/immune-gmbh/attestation-sdk/pkg/uefi"
)

type originalFirmwareInput struct {
	FirmwareImage OriginalFirmwareBlob
}

func getOriginalFirmware(ctx context.Context, in originalFirmwareInput) (OriginalFirmware, []Issue, error) {
	fw, err := uefi.Parse(in.FirmwareImage.Bytes(), false)
	if err != nil {
		err = fmt.Errorf("failed to parse UEFI firmware: %w", err)
		logger.FromCtx(ctx).Errorf("%v", err)
		return OriginalFirmware{}, nil, err
	}
	return NewOriginalFirmware(fw, in.FirmwareImage), nil, nil
}

type actualFirmwareInput struct {
	FirmwareImage ActualFirmwareBlob
}

func getActualFirmware(ctx context.Context, in actualFirmwareInput) (ActualFirmware, []Issue, error) {
	fw, err := uefi.Parse(in.FirmwareImage.Bytes(), false)
	if err != nil {
		err = fmt.Errorf("failed to parse UEFI firmware: %w", err)
		logger.FromCtx(ctx).Errorf("%v", err)
		return ActualFirmware{}, nil, err
	}
	return NewActualFirmware(fw, in.FirmwareImage), nil, nil
}

type actualPSPFirmwareInput struct {
	Firmware ActualFirmware
}

func getActualPSPFirmware(ctx context.Context, in actualPSPFirmwareInput) (ActualPSPFirmware, []Issue, error) {
	log := logger.FromCtx(ctx)
	if !pcr.IsAMDPSPFirmware(ctx, in.Firmware.UEFI()) { // TODO: use `bootflow.*`, instead of `pcr.*`
		log.Infof("not an AMD PSP firmware")
		return ActualPSPFirmware{}, nil, NewErrNotApplicable("non AMD PSP firmware")
	}
	amdFW, err := amd_manifest.NewAMDFirmware(in.Firmware.UEFI())
	if err != nil {
		log.Errorf("Failed to parse AMD firmware: %v", err)
		return ActualPSPFirmware{}, nil, err
	}
	return NewActualPSPFirmware(amdFW, in.Firmware.Blob), nil, nil
}

type fixedRegistersInput struct {
	ActualFirmware   ActualFirmwareBlob
	OriginalFirmware OriginalFirmware        `exec:"optional"`
	AlignedImage     AlignedOriginalFirmware `exec:"optional"`
	Regs             ActualRegisters
	EventLog         *tpmeventlog.TPMEventLog `exec:"optional"`
	PCR0             ActualPCR0               `exec:"optional"`
}

// getFixedRegisters tries to fix values of some registers that might be affected by known problems.
// Previously we observed that some hosts had corrupted value of ACM_POLICY_STATUS register which changed after
// an appropriate measurement was taken due to issues in Intel's firmware
func getFixedRegisters(ctx context.Context, in fixedRegistersInput) (FixedRegisters, []Issue, error) {
	log := logger.FromCtx(ctx)

	actualImage := in.ActualFirmware.Bytes()
	referenceFW := in.OriginalFirmware.UEFI()
	offset := uint64(0)
	if in.AlignedImage.UEFI() != nil {
		referenceFW = in.OriginalFirmware.UEFI()
	}

	// We might not have the "original" firmware, so try to fix registers using actual firmware only
	//
	// TODO: use a datacalculator to provide a reference firmware, instead of putting this logic
	//       into an analyzer
	if referenceFW == nil {
		var err error
		referenceFW, err = uefi.Parse(actualImage, false)
		if err != nil {
			return FixedRegisters{}, nil, fmt.Errorf("the original image is not provided, and cannot parse the actual image: %w", err)
		}
	}

	if !pcr.IsCBnTFirmware(referenceFW) { // TODO: use `bootflow.*`, instead of `pcr.*`
		log.Infof("Not a CBnT firmware, assume registers are correct")
		res, err := NewFixedRegisters(in.Regs.GetRegisters())
		if err != nil {
			return FixedRegisters{}, nil, err
		}
		return res, nil, nil
	}
	if in.EventLog == nil && len(in.PCR0) == 0 {
		log.Infof("Not enough input data to check registers, assume input registers are correct")
		res, err := NewFixedRegisters(in.Regs.GetRegisters())
		if err != nil {
			return FixedRegisters{}, nil, err
		}
		return res, []Issue{
			{
				Severity:    SeverityInfo,
				Description: "Not enough data to check registers correctness",
			},
		}, nil
	}

	fixedRegs, mIssues, fixErr := measurements.GetFixedHostConfiguration(
		ctx,
		referenceFW,
		offset,
		actualImage,
		in.Regs.GetRegisters(),
		in.EventLog,
		in.PCR0,
	)
	var issues []Issue
	for _, mIssue := range mIssues {
		issues = append(issues, Issue{
			Severity:    SeverityInfo,
			Description: fmt.Sprintf("an issue of getting fixed host configuration: %s", mIssue.Error()),
		})
	}
	if fixErr != nil {
		log.Infof("Failed to check registers: '%v', assume input registers are correct", fixErr)
		res, err := NewFixedRegisters(in.Regs.GetRegisters())
		if err != nil {
			return FixedRegisters{}, issues, err
		}
		issues = append(issues, Issue{
			Severity:    SeverityInfo,
			Description: fmt.Sprintf("Failed to check registers: %v", fixErr),
		})
		return res, issues, nil
	}

	for _, reg := range in.Regs.GetRegisters() {
		fixedReg := fixedRegs.Find(reg.ID())
		if fixedReg == nil {
			issues = append(issues, Issue{
				Severity:    SeverityInfo,
				Description: fmt.Sprintf("register '%s' is not expected", reg.ID()),
			})
			continue
		}
		oldValue, err := registers.ValueBytes(reg)
		if err != nil {
			return FixedRegisters{}, issues, err
		}
		newValue, err := registers.ValueBytes(fixedReg)
		if err != nil {
			return FixedRegisters{}, issues, err
		}
		if !bytes.Equal(oldValue, newValue) {
			issues = append(issues, Issue{
				Severity:    SeverityInfo,
				Description: fmt.Sprintf("register's '%s' value was changed from '%X' to '%X'", reg.ID(), oldValue, newValue),
			})
		}
	}
	res, err := NewFixedRegisters(fixedRegs)
	if err != nil {
		return FixedRegisters{}, issues, err
	}
	return res, issues, nil
}

type getAlignedOriginalImageInput struct {
	OriginalFirmware OriginalFirmware
	ActualFirmware   ActualFirmwareBlob
}

func getAlignedOriginalImage(ctx context.Context, in getAlignedOriginalImageInput) (AlignedOriginalFirmware, []Issue, error) {
	log := logger.FromCtx(ctx)
	alignedImage, offset, err := imgalign.GetAlignedImage(ctx, in.OriginalFirmware.UEFI(), in.ActualFirmware.Bytes())
	if err != nil {
		err = fmt.Errorf("failed to align original and dumped firmware images: '%v'", err)
		log.Errorf("%v", err)
		return AlignedOriginalFirmware{}, nil, err
	}
	log.Infof("Aligned images offset: %d", offset)
	return NewAlignedOriginalFirmware(alignedImage, offset, in.OriginalFirmware.Blob), nil, nil
}

type getReferenceFirmwareInput struct {
	AlignedOriginalFirmware *AlignedOriginalFirmware `exec:"optional"`
	ActualFirmware          ActualFirmware
}

func getReferenceFirmware(ctx context.Context, in getReferenceFirmwareInput) (ReferenceFirmware, []Issue, error) {
	refFirmware, err := NewReferenceFirmware(ctx, in.AlignedOriginalFirmware, &in.ActualFirmware)
	if refFirmware == nil {
		return ReferenceFirmware{}, nil, err
	}

	var issues []Issue
	if err != nil {
		issues = []Issue{{
			Custom:      err,
			Severity:    SeverityWarning,
			Description: err.Error(),
		}}
	}

	return *refFirmware, issues, nil
}

type getActualBIOSInfoInput struct {
	ActualFirmwareBlob ActualFirmwareBlob
}

func getActualBIOSInfo(ctx context.Context, in getActualBIOSInfoInput) (ActualBIOSInfo, []Issue, error) {
	r, err := dmidecode.DMITableFromFirmwareImage(in.ActualFirmwareBlob.Bytes())
	if err != nil {
		return ActualBIOSInfo{}, nil, err
	}
	return ActualBIOSInfo{BIOSInfo: r.BIOSInfo()}, nil, nil
}

type getOriginalBIOSInfoInput struct {
	OriginalFirmwareBlob OriginalFirmwareBlob
}

func getOriginalBIOSInfo(ctx context.Context, in getOriginalBIOSInfoInput) (OriginalBIOSInfo, []Issue, error) {
	r, err := dmidecode.DMITableFromFirmwareImage(in.OriginalFirmwareBlob.Bytes())
	if err != nil {
		return OriginalBIOSInfo{}, nil, err
	}
	return OriginalBIOSInfo{BIOSInfo: r.BIOSInfo()}, nil, nil
}

type bootFlowUpstreamToDownstreamInput struct {
	UpstreamTypedValue bootflowtypes.Flow
}

func bootFlowUpstreamToDownstream(ctx context.Context, in bootFlowUpstreamToDownstreamInput) (types.BootFlow, []Issue, error) {
	return types.BootFlow(in.UpstreamTypedValue), nil, nil
}

func bootFlowDefault(ctx context.Context, in struct{}) (bootflowtypes.Flow, []Issue, error) {
	return flows.Root, nil, nil
}

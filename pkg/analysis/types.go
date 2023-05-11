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
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/dmidecode"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

func init() {
	RegisterType((*types.BootFlow)(nil))
	RegisterType((BytesBlob)(nil))
	RegisterType((*OriginalFirmwareBlob)(nil))
	RegisterType((*ActualFirmwareBlob)(nil))
	RegisterType((*ActualRegisters)(nil))
	RegisterType((tpmdetection.Type)(0))
	RegisterType((*tpmeventlog.TPMEventLog)(nil))
	RegisterType((ActualPCR0)(nil))
	RegisterType((AssetID)(0))
	RegisterType((*OriginalBIOSInfo)(nil))
	RegisterType((*ActualBIOSInfo)(nil))
	RegisterType((*ReferenceFirmware)(nil))
}

// AnalyzerID is a unique ID of every analyzer
//
// TODO: consider replacing unique indexes with reflect.TypeOf(input) to have a single source of truth
type AnalyzerID string

// Analyzer is an abstract interface that each analyzer should implement
type Analyzer[inputType any] interface {
	ID() AnalyzerID
	Analyze(context.Context, inputType) (*Report, error)
}

// ActualPSPFirmware represents parsed original AMD PSP firmware (the one we get from the orig firmware table and expect to be installed on the host)
type ActualPSPFirmware struct {
	Blob  Blob // contributes to the cache key
	amdFW *amd_manifest.AMDFirmware
}

// AMDFirmware returns an AMDFirmware object
func (af ActualPSPFirmware) AMDFirmware() *amd_manifest.AMDFirmware {
	return af.amdFW
}

// NewActualPSPFirmware creates a new ActualPSPFirmware object from firmware.
//
// `blob` is optional, if not provided, then amdFW.Firmware().ImageBytes() is used instead.
func NewActualPSPFirmware(amdFW *amd_manifest.AMDFirmware, blob Blob) ActualPSPFirmware {
	if blob == nil {
		blob = BytesBlob(amdFW.Firmware().ImageBytes())
	}
	return ActualPSPFirmware{
		Blob:  blob,
		amdFW: amdFW,
	}
}

// OriginalFirmware represents parsed original firmware (the one we get from the orig firmware table and expect to be installed on the host)
type OriginalFirmware struct {
	Blob // contributes into cache key
	fw   *uefi.UEFI
}

// UEFI returns an UEFI object of OriginalFirmware
func (of OriginalFirmware) UEFI() *uefi.UEFI {
	return of.fw
}

// NewOriginalFirmware creates a new OriginalFirmware object from firmware.
//
// `blob` is optional, if not provided, then fw.Buf() is used instead.
func NewOriginalFirmware(fw *uefi.UEFI, blob Blob) OriginalFirmware {
	if blob == nil {
		blob = BytesBlob(fw.Buf())
	}
	return OriginalFirmware{
		Blob: blob,
		fw:   fw,
	}
}

// OriginalFirmwareBlob represents raw bytes of the original firmware image
type OriginalFirmwareBlob struct {
	Blob
}

// NewOriginalFirmwareBlob creates a new OriginalFirmwareBlob object
func NewOriginalFirmwareBlob(image Blob) OriginalFirmwareBlob {
	return OriginalFirmwareBlob{Blob: image}
}

// ActualFirmwareBlob represents raw bytes of the actual firmware image (the one obtained from the host)
type ActualFirmwareBlob struct {
	Blob
}

// NewActualFirmwareBlob creates a new ActualFirmwareBlob object
func NewActualFirmwareBlob(image Blob) ActualFirmwareBlob {
	return ActualFirmwareBlob{Blob: image}
}

// ActualFirmware represents parsed actual firmware (the one we dump)
type ActualFirmware struct {
	Blob // contributes into cache key
	fw   *uefi.UEFI
}

// UEFI returns an UEFI object of ActualFirmware
func (of ActualFirmware) UEFI() *uefi.UEFI {
	return of.fw
}

// NewActualFirmware creates a new ActualFirmware object from firmware.
//
// `blob` is optional, if not provided, then fw.Buf() is used instead.
func NewActualFirmware(fw *uefi.UEFI, blob Blob) ActualFirmware {
	if blob == nil {
		blob = BytesBlob(fw.Buf())
	}
	return ActualFirmware{
		Blob: blob,
		fw:   fw,
	}
}

// ActualRegisters represents the actual registers (the one obtained from the host)
type ActualRegisters struct {
	Regs     registers.Registers
	regsHash objhash.ObjHash
}

// NewActualRegisters creates new ActualRegisters object
func NewActualRegisters(regs registers.Registers) (ActualRegisters, error) {
	regsHash, err := cacheRegisters(regs)
	if err != nil {
		return ActualRegisters{}, err
	}
	return ActualRegisters{
		Regs:     regs,
		regsHash: regsHash,
	}, nil
}

// GetRegisters returns registers
func (ar ActualRegisters) GetRegisters() registers.Registers {
	return ar.Regs
}

// CacheWrite is an implementation of objhash.Custom interface
func (ar ActualRegisters) CacheWrite(b *objhash.Builder) error {
	return b.Write(ar.regsHash)
}

var _ objhash.Custom = ActualRegisters{}

// FixedRegisters represents registers that have been fixed in accordance with other information obtained from the host
type FixedRegisters struct {
	Regs     registers.Registers
	regsHash objhash.ObjHash
}

// NewFixedRegisters creates new ActualRegisters object
func NewFixedRegisters(regs registers.Registers) (FixedRegisters, error) {
	regsHash, err := cacheRegisters(regs)
	if err != nil {
		return FixedRegisters{}, err
	}
	return FixedRegisters{
		Regs:     regs,
		regsHash: regsHash,
	}, nil
}

// GetRegisters returns registers
func (fr FixedRegisters) GetRegisters() registers.Registers {
	return fr.Regs
}

// CacheWrite is an implementation of objhash.Custom interface
func (fr FixedRegisters) CacheWrite(b *objhash.Builder) error {
	return b.Write(fr.regsHash)
}

var _ objhash.Custom = FixedRegisters{}

// ActualPCR0 represents an actual PCR0 value of the host
type ActualPCR0 []byte

// AlignedOriginalFirmware represents a part of the original image which is aligned with the DumpedFirmware image.
//
// Often the only region we can dump from the target is BIOS region, while the original image usually consists
// of multiple regions (and the BIOS region is the last one). So the aligned image is a such image that has
// an offset (to start with the same thing as the dumped firmware) and the same length as the dumped firmware.
type AlignedOriginalFirmware struct {
	Blob        Blob
	ImageOffset uint64
	fw          *uefi.UEFI
}

// UEFI returns an UEFI object of AlignedOriginalImage
func (ao AlignedOriginalFirmware) UEFI() *uefi.UEFI {
	return ao.fw
}

// NewAlignedOriginalFirmware creates new AlignedOriginalImage object
//
// `blob` is optional, if not provided, then fw.Buf() is used instead.
func NewAlignedOriginalFirmware(fw *uefi.UEFI, offset uint64, blob Blob) AlignedOriginalFirmware {
	if blob == nil {
		blob = BytesBlob(fw.ImageBytes())
	}
	return AlignedOriginalFirmware{
		Blob:        blob,
		ImageOffset: offset,
		fw:          fw,
	}
}

// ReferenceFirmware is a firmware used as the reference.
// It is the aligned original firmware if it is available,
// or just the actual firmware otherwise.
type ReferenceFirmware struct {
	Blob        Blob
	ImageOffset uint64
	fw          *uefi.UEFI
}

// UEFI returns an UEFI object of AlignedOriginalImage
func (rf ReferenceFirmware) UEFI() *uefi.UEFI {
	return rf.fw
}

// NewReferenceFirmware creates new ReferenceFirmware object.
//
// If alignedOriginalFirmware is nil then actualFirmware will be used as the reference firmware.
func NewReferenceFirmware(ctx context.Context, alignedOriginalFirmware *AlignedOriginalFirmware, actualFirmware *ActualFirmware) (*ReferenceFirmware, error) {
	switch {
	case alignedOriginalFirmware != nil:
		return &ReferenceFirmware{
			Blob:        alignedOriginalFirmware.Blob,
			ImageOffset: alignedOriginalFirmware.ImageOffset,
			fw:          alignedOriginalFirmware.fw,
		}, nil
	case actualFirmware != nil:
		return &ReferenceFirmware{
			Blob:        actualFirmware.Blob,
			ImageOffset: 0,
			fw:          actualFirmware.fw,
		}, fmt.Errorf("original image is not available as the reference image, thus using the actual image instead")
	default:
		return nil, fmt.Errorf("both original and actual firmwares are nil")
	}
}

// AssetID represents information about the asset id of the host that is being analyzed
type AssetID int64

func cacheRegisters(regs registers.Registers) (objhash.ObjHash, error) {
	sortedRegs := make([]registers.Register, 0, len(regs))
	for _, reg := range regs {
		sortedRegs = append(sortedRegs, reg)
	}
	sort.Slice(sortedRegs, func(i, j int) bool {
		return strings.Compare(string(regs[i].ID()), string(regs[i].ID())) == -1
	})

	builder := objhash.NewBuilder()
	builder.Build(len(regs))

	for _, reg := range sortedRegs {
		b, err := registers.ValueBytes(reg)
		if err != nil {
			return objhash.ObjHash{}, err
		}
		if err := builder.Write(reg.ID()); err != nil {
			return objhash.ObjHash{}, err
		}
		if err := builder.Write(b); err != nil {
			return objhash.ObjHash{}, nil
		}
	}
	return builder.Result(), nil
}

// ActualBIOSInfo represents data stored in the SMBIOS of the actual image.
type ActualBIOSInfo struct {
	dmidecode.BIOSInfo
}

// NewActualBIOSInfo creates a new instance of ActualBIOSInfo
func NewActualBIOSInfo(biosInfo dmidecode.BIOSInfo) *ActualBIOSInfo {
	return &ActualBIOSInfo{BIOSInfo: biosInfo}
}

// OriginalBIOSInfo represents data stored in the SMBIOS of the original image.
type OriginalBIOSInfo struct {
	dmidecode.BIOSInfo
}

// NewOriginalBIOSInfo creates a new instance of OriginalBIOSInfo
func NewOriginalBIOSInfo(biosInfo dmidecode.BIOSInfo) *OriginalBIOSInfo {
	return &OriginalBIOSInfo{BIOSInfo: biosInfo}
}

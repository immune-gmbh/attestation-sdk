//go:build linux
// +build linux

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

package flashrom

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/facebookincubator/go-belt/tool/logger"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/uefi"
)

const (
	devMemSkipPlaceholderHead = true
)

func (f *flashrom) findBIOSRegionUsingIOMem() (*pkgbytes.Range, error) {
	// This is a desperate way to find coordinates of the BIOS region
	// in the physical memory.
	//
	// The it is known that some systems maps the BIOS region to address
	// below 0x100000000 (0xffffffff and below), few examples:
	// * https://cdrdv2.intel.com/v1/dl/getContent/599500
	// * https://github.com/tianocore/edk2/blob/cbccf995920a28071f5403b847f29ebf8b732fa9/OvmfPkg/README
	//
	// So our strategy here is just to find memory region which ends
	// with 0xffffffff and assume it is the BIOS region.

	iomem, err := f.getIOMem()
	if err != nil {
		return nil, fmt.Errorf("unable to get iomem data: %w", err)
	}

	var biosIOMemEntry *IOMemEntry
	for _, iomemEntry := range iomem {
		if iomemEntry.End == 0xffffffff {
			biosIOMemEntry = iomemEntry
			break
		}
	}
	if biosIOMemEntry == nil {
		return nil, fmt.Errorf("unable to find BIOS entry in '%s'", f.Config.IOMemPath)
	}

	// The `/proc/iomem` format uses inclusive starting and ending indexes,
	// while in Go we usually treat the ending index as non-inclusive one, so we
	// add "+1" to the end.

	if (biosIOMemEntry.End + 1) < biosIOMemEntry.Start {
		return nil, fmt.Errorf("the end is earlier than the start: %d < %d", biosIOMemEntry.End+1, biosIOMemEntry.Start)
	}

	return &pkgbytes.Range{
		Offset: biosIOMemEntry.Start,
		Length: (biosIOMemEntry.End + 1) - biosIOMemEntry.Start,
	}, nil
}

func (f *flashrom) dumpDevMem(ctx context.Context) ([]byte, error) {
	biosRange, err := f.findBIOSRegionUsingIOMem()
	if err != nil {
		return nil, fmt.Errorf("unable to find the BIOS region range: %w", err)
	}

	devMemFile, err := os.OpenFile(f.Config.DevMemPath, os.O_RDONLY, 0000)
	if err != nil {
		return nil, fmt.Errorf("unable to open '%s': %w", f.Config.DevMemPath, err)
	}

	_, err = devMemFile.Seek(int64(biosRange.Offset), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("unable to seek(%d, %d) on '%s': %w",
			int64(biosRange.Offset), io.SeekStart, f.Config.DevMemPath, err)
	}

	firmwareSize := biosRange.Length
	b := make([]byte, firmwareSize)
	r, err := devMemFile.Read(b)
	if err != nil {
		return nil, fmt.Errorf("unable to read '%s' at %d: %w", f.Config.DevMemPath, biosRange.Offset, err)
	}
	if uint64(r) != firmwareSize {
		return nil, fmt.Errorf("received wrong length: %d != %d", r, firmwareSize)
	}

	if devMemSkipPlaceholderHead {
		placeholderWordLength := 0x10000
		origLength := len(b)
		placeholderWord := make([]byte, placeholderWordLength)
		for idx := range placeholderWord {
			placeholderWord[idx] = 0xff
		}
		for bytes.HasPrefix(b, placeholderWord) {
			b = b[placeholderWordLength:]
		}
		if len(b) < origLength {
			logger.FromCtx(ctx).Warnf("the beginning of dumped image is filled with 0xFF; after removing the placeholder the length reduced from 0x%X (%d) to 0x%X (%d) bytes", origLength, origLength, len(b), len(b))
		}
	}

	// Verifying if this is indeed a BIOS region.
	_, err = uefi.Parse(b)
	if err != nil {
		return b, fmt.Errorf("received memory region is not a valid BIOS region: %w", err)
	}

	return b, nil
}

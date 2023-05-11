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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/facebookincubator/go-belt/tool/logger"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
)

func (f *flashrom) dumpMTD(ctx context.Context) ([]byte, error) {
	devName, err := f.findBIOSMTDDevName()
	if err != nil {
		return nil, fmt.Errorf("unable to find an MTD device storing BIOS: %w", err)
	}

	mtdMeta, err := f.readMTDMeta(devName)
	if err != nil {
		return nil, fmt.Errorf("unable to collect MTD '%s' metadata: %w", devName, err)
	}

	image, err := f.readMTD(*mtdMeta)
	if err == nil {
		// Everything is good, return :)
		return image, nil
	}
	if !errors.Is(err, syscall.EIO) {
		// Unknown error, return :(
		return nil, fmt.Errorf("unable to read image from MTD '%s': %w", devName, err)
	}

	// OK, here we have an syscall.EIO error.
	//
	// So far it is known that this problem happens when the firmware is not actually placed
	// in the beginning of the MTD address space.
	// In this case we __ASSUME__ the image is placed in the end of the MTD address space.
	// So we just calculate the offset as: mtdEndOffset - imageSize.

	logger.FromCtx(ctx).Warnf("unable to read image from MTD '%s': %v. Trying to find a proper offset using '%s', assuming the firmware image ends in the end of the MTD device address space...",
		devName, err, f.Config.IOMemPath)

	// We get the size of the image according to IOMem map.
	biosRange, err2 := f.findBIOSRegionUsingIOMem()
	if err2 != nil {
		return nil, fmt.Errorf("unable to find the BIOS region range: %w", err2)
	}
	// A note: the offset from `findBIOSRegionUsingIOMem` is the offset in
	// the physical memory address space. While MTD has another address space.
	// Thus we cannot just use the offset from `findBIOSRegionUsingIOMem`.
	// Instead we calculate the offset as: mtdEndOffset - imageSize.

	if biosRange.Length >= mtdMeta.Length {
		// If the lengths are equal then the resulting offset will be zero,
		// and this offset we already tried above.
		return nil, fmt.Errorf("unable to read image from MTD '%s' due to an EIO error and cannot find a better offset: %d >= %d: %w", devName, biosRange.Length, mtdMeta.Length, err)
	}
	mtdMeta.Offset = mtdMeta.Length - biosRange.Length

	image, err2 = f.readMTD(*mtdMeta)
	if err2 != nil {
		return nil, fmt.Errorf("unable to read image from MTD '%s' due to an EIO error (%w) and an attempt to read with offset %d also resulted into error: %v", devName, err, mtdMeta.Offset, err2)
	}

	return image, nil
}

func (f *flashrom) findBIOSMTDDevName() (string, error) {
	entries, err := os.ReadDir(f.Config.SysFSMTDPath)
	if err != nil {
		return "", fmt.Errorf("unable to open dir '%s': %w", f.Config.SysFSMTDPath, err)
	}

	var otherStorages []string
	for _, entry := range entries {
		namePath := filepath.Join(f.Config.SysFSMTDPath, entry.Name(), "name")
		nameBytes, err := os.ReadFile(namePath)
		if err != nil {
			return "", fmt.Errorf("unable to read the name of the storage '%s': %w", entry.Name(), err)
		}

		storageName := strings.ToUpper(strings.Trim(string(nameBytes), "\n"))

		// Linux driver "intel-spi" publishes the BIOS region with name "BIOS".
		// Currently we do not support any other platform.
		if storageName == "BIOS" {
			return entry.Name(), nil
		}

		otherStorages = append(otherStorages, storageName)
	}

	return "", fmt.Errorf("unable to find the BIOS storage in MTDs listed in '%s', instead found: %v", f.Config.SysFSMTDPath, otherStorages)
}

type mtdMeta struct {
	pkgbytes.Range
	Name string
}

func (f *flashrom) readMTDMeta(devName string) (*mtdMeta, error) {
	mtdMetaPath := filepath.Join(f.Config.SysFSMTDPath, devName)

	readUint64From := func(path string) (uint64, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("unable to read file '%s': %w", path, err)
		}
		v, err := strconv.ParseUint(strings.Trim(string(b), "\n"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("unable to parse unsigned integer '%s' from file '%s': %w", b, path, err)
		}
		return v, nil
	}

	size, err := readUint64From(filepath.Join(mtdMetaPath, "size"))
	if err != nil {
		return nil, fmt.Errorf("unable to read the size of the storage: %w", err)
	}
	offset, err := readUint64From(filepath.Join(mtdMetaPath, "offset"))
	if err != nil {
		return nil, fmt.Errorf("unable to read the offset on the storage: %w", err)
	}

	return &mtdMeta{
		Range: pkgbytes.Range{
			Offset: offset,
			Length: size,
		},
		Name: devName,
	}, nil
}

func (f *flashrom) readMTD(mtdMeta mtdMeta) ([]byte, error) {
	devPath := filepath.Join(f.Config.DevPath, mtdMeta.Name)
	dev, err := os.Open(devPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open device")
	}
	defer dev.Close()

	length := mtdMeta.Length - mtdMeta.Offset
	result := make([]byte, length)
	if _, err := dev.ReadAt(result, int64(mtdMeta.Offset)); err != nil {
		return nil, fmt.Errorf("unable to read from '%s' at %d: %w", devPath, int64(mtdMeta.Offset), err)
	}

	return result, nil
}

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

package firmwarerepo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"

	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
	fiano "github.com/linuxboot/fiano/pkg/uefi"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/immune-gmbh/attestation-sdk/pkg/uefi"
)

// ExtractFirmwareImage tries to extract firmware image from the data obtained by FirmwareStorage
func ExtractFirmwareImage(ctx context.Context, originalFilename string, data []byte) (*uefi.UEFI, string, error) {
	if fw := ParseFirmwareImage(ctx, data); fw != nil {
		return fw, originalFilename, nil
	}
	logger.FromCtx(ctx).Debugf("Unknown firmware image, try to decompress it")
	uefi, filename, err := ExtractFirmwareFromTarball(ctx, data)
	if err != nil {
		return nil, "", ErrUnknownFirmwareImage{}
	}
	return uefi, filename, nil
}

// ParseFirmwareImage checks if input data represents a firmware image
func ParseFirmwareImage(ctx context.Context, data []byte) *uefi.UEFI {
	log := logger.FromCtx(ctx)
	firmware, err := uefi.Parse(data, true) // TODO: replace "true" with "false" when "bootflow" will have lazy decompression
	if err != nil {
		log.Debugf("Unable to parse UEFI: %v", err)
		return nil
	}

	if _, ok := firmware.Firmware.(*fiano.FlashImage); ok {
		log.Debugf("Is a flash image")
		return firmware
	}

	if _, _, err := amd_manifest.FindEmbeddedFirmwareStructure(firmware); err == nil {
		log.Debugf("Is an AMD firmware image")
		return firmware
	}
	return nil
}

// ExtractFirmwareFromTarball returns a firmware image extracted from tarball.
func ExtractFirmwareFromTarball(ctx context.Context, tarball []byte) (*uefi.UEFI, string, error) {
	// Unfortunately there was found no good way to extract a firmware image
	// (there's no everstore handle filled in the orig firmware table).
	//
	// So we just try to parse each file and return the one which is
	// successfully parsed.
	log := logger.FromCtx(ctx)

	gzReader, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, "", fmt.Errorf("unable to initialize gzip-decompressor: %w", err)
	}

	tarReader := tar.NewReader(gzReader)

	for {
		hdr, err := tarReader.Next()
		if err != nil {
			if err != io.EOF {
				return nil, "", fmt.Errorf("unable to read file headers from the tarball: %w", err)
			}
			break
		}
		log.Debugf("got '%s' file", hdr.Name)

		if hdr.Size < 1024 {
			// just in case
			log.Debugf("'%s' is small", hdr.Name)
			continue
		}

		data, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, "", fmt.Errorf("unable to read file '%s': %w", hdr.Name, err)
		}

		fw := ParseFirmwareImage(ctx, data)
		if fw == nil {
			continue
		}
		log.Debugf("%s: a firmware image", hdr.Name)
		return fw, hdr.Name, nil
	}

	return nil, "", ErrNoFirmwareFoundInTarGZ{}
}

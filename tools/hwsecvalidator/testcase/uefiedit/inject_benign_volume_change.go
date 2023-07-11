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
package uefiedit

import (
	"encoding/binary"
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/tools/hwsecvalidator/testcase/errors"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs"
	"github.com/hashicorp/go-multierror"
	"github.com/linuxboot/fiano/pkg/guid"
	fianoUEFI "github.com/linuxboot/fiano/pkg/uefi"
)

// InjectBenignVolumeChange modifies the specified volume in a benign way (so that it is still bootable).
//
// The volume is selected through GUID (first met among provided).
//
// If `corruptionDistance` is zero then the distance is chosen automatically.
func InjectBenignVolumeChange(
	image []byte,
	corruptionDistance uint64,
	guids ...guid.GUID,
) error {
	fianoUEFI.DisableDecompression = true
	fianoUEFI.ReadOnly = true
	firmware, err := uefi.ParseUEFIFirmwareBytes(image)
	if err != nil {
		return errors.ErrParseFirmware{Err: err}
	}

	var volume *ffs.Node
	for _, _guid := range guids {
		volumes, err := firmware.GetByGUID(_guid)
		if len(volumes) == 0 {
			continue
		}
		if err != nil {
			return errors.ErrParseFirmware{Err: fmt.Errorf("unable to look for volume '%s', err: %w", _guid, err)}
		}
		volume = volumes[0]
		break
	}
	if volume == nil {
		return errors.ErrParseFirmware{Err: fmt.Errorf("unable find volumes: %v", guids)}
	}

	var mErr *multierror.Error
	err = injectBenignVolumeChangeInPaddingFile(image, corruptionDistance, volume)
	if err == nil {
		return nil
	}
	mErr = multierror.Append(mErr, err)

	err = injectBenignVolumeChangeInHeaders(image, corruptionDistance, volume)
	if err == nil {
		return nil
	}
	mErr = multierror.Append(mErr, err)

	return mErr
}

func injectBenignVolumeChangeInPaddingFile(
	image []byte,
	corruptionDistance uint64,
	volume *ffs.Node,
) error {
	var padFile *fianoUEFI.File
	for _, file := range volume.Firmware.(*fianoUEFI.FirmwareVolume).Files {
		if len(file.Buf()) < int(corruptionDistance)+24 {
			// TODO: add support of multibit corruption per byte.
			continue
		}
		if file.Header.Type == fianoUEFI.FVFileTypePad {
			padFile = file
			break
		}
	}
	if padFile == nil {
		return errors.ErrModify{Err: fmt.Errorf("unable to find a big enough padding file")}
	}

	if corruptionDistance == 0 {
		corruptionDistance = 1
	}

	for i := 0; i < int(corruptionDistance); i++ {
		padFile.Buf()[len(padFile.Buf())-int(i)-1] ^= 0x01
	}
	return nil
}

func injectBenignVolumeChangeInHeaders(
	image []byte,
	corruptionDistance uint64,
	node *ffs.Node,
) error {
	if corruptionDistance != 0 {
		return fmt.Errorf("custom corruption distances not supported, yet: requested %d", corruptionDistance)
	}

	volume, ok := node.Firmware.(*fianoUEFI.FirmwareVolume)
	if !ok {
		return fmt.Errorf("internal error: should never happen: the UEFI object is %T, but expected *uefi.FirmwareVolume", node.Firmware)
	}

	// Flipping a bit in field "Reserved"

	reservedOffset := node.Offset + 16 + 16 + 8 + 4 + 4 + 2 + 2 + 2
	image[reservedOffset] ^= 0x01

	// Recalculating the checksum after that, to make sure we do not
	// disrupt the boot process.

	checksumOffset := node.Offset + 16 + 16 + 8 + 4 + 4 + 2

	// zeroing the checksum field, to calculate the checksum of the whole headers structure
	binary.LittleEndian.PutUint16(image[checksumOffset:], 0)
	// calculating
	newChecksum, err := fianoUEFI.Checksum16(image[node.Offset : node.Offset+uint64(volume.HeaderLen)])
	if err != nil {
		return fmt.Errorf("unable to recalculate the checksum of the volume: %w", err)
	}
	newChecksum = 0 - newChecksum // otherwise the checksum is invalid, IDK
	// setting
	binary.LittleEndian.PutUint16(image[checksumOffset:], newChecksum)
	return nil
}

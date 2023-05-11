package uefiedit

import (
	"encoding/binary"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase/errors"

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

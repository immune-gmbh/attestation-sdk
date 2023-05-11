package firmwarewand

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/uefi"
)

// FindImage returns the metadata of the image stored in Manifold
func (fwwand *FirmwareWand) FindImage(
	ctx context.Context,
	imageBytes []byte,
) *afas.FirmwareImageMetadata {
	l := logger.FromCtx(ctx)

	// We will look for an image using PCR0 values. This solution is not stable
	// to statusRegisters (which are outside of the image), but this is the
	// best we can do at the moment.

	firmware, err := uefi.Parse(imageBytes, false)
	if err != nil {
		l.Infof("unable to calculate parse the firmware: %v", err)
		return nil
	}

	hashStable, err := types.NewImageStableHash(firmware)
	if err != nil {
		l.Warnf("unable to calculate a stable hash for the image: %v", err)
		return nil
	}

	entries, err := fwwand.afasClient.SearchFirmware(ctx, &afas.SearchFirmwareRequest{OrFilters: []*afas.SearchFirmwareFilters{{
		HashStable: hashStable,
	}}})
	l.Debugf("search result is-nil:%v; err-result is: %v", entries == nil, err)

	if entries == nil || len(entries.Found) == 0 {
		return nil
	}

	if len(entries.Found) > 1 {
		l.Errorf("search resulted in multiple return values")
	}
	return entries.Found[0].GetMetadata()
}

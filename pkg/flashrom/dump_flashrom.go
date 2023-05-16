//go:build linux
// +build linux

package flashrom

import (
	"context"
	"fmt"
	"time"
)

func (f *flashrom) dumpFlashrom(ctx context.Context) ([]byte, error) {
	// We execute an external tool which add a lot of unpredictability,
	// for example it could hang for some reason. Therefore we use
	// a timeout.
	//
	// We expect flashrom to handle the request in ~3-20 seconds, but
	// to be sure we wait up to 5 minutes.
	ctx, cancelFunc := context.WithTimeout(ctx, time.Minute*5)
	defer cancelFunc()

	imageBytes, err := f.execReceive(ctx, f.Config.FlashromPath,
		"-p", "internal:laptop=this_is_not_a_laptop,ich_spi_mode=hwseq",
		"--ifd",
		"-i", "bios",
		"-r", outputPathArgument,
	)
	if err == nil {
		return imageBytes, nil
	}
	if f.Config.FirmwareFallbackLayoutPath == `` {
		return nil, fmt.Errorf("unable to extract firmware (with automatic layout detection): %w", err)
	}

	imageBytes, err = f.execReceive(ctx, f.Config.FlashromPath,
		"-p", "internal:laptop=this_is_not_a_laptop,ich_spi_mode=hwseq",
		"--layout", f.Config.FirmwareFallbackLayoutPath,
		"-i", "bios",
		"-r", outputPathArgument,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to extract firmware (with fallback layout): %w", err)
	}
	return imageBytes, nil
}

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

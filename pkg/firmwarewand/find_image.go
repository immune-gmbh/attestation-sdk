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

package firmwarewand

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/uefi"
)

// FindImage returns the metadata of the image stored in BlobStorage
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

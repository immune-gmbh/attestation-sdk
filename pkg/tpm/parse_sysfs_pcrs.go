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
package tpm

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"strings"
)

const tpm12PCRsPath = `/sys/class/tpm/tpm0/pcrs`

const amountOfPCRs = 24

func parseSysfsPCRs(data []byte) ([amountOfPCRs][]byte, error) {
	var pcrs [amountOfPCRs][]byte
	// See a sample in the unit-test.

	for lineNum, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var pcrIndex int
		var pcrValue []byte
		_, err := fmt.Sscanf(strings.ReplaceAll(string(line), " ", ""), "PCR-%02d:%X", &pcrIndex, &pcrValue)
		if err != nil {
			return pcrs, fmt.Errorf("unable to scan line '%s': %w", line, err)
		}
		if lineNum != pcrIndex {
			return pcrs, fmt.Errorf("unexpected PCRs order: expected:%d, received:%d", lineNum, pcrIndex)
		}
		if len(pcrValue) != sha1.Size {
			return pcrs, fmt.Errorf("expected SHA1 with length: 20 bytes, but received length %d: 0x%X (raw value: '%s')", len(pcrValue), pcrValue, line)
		}
		pcrs[pcrIndex] = pcrValue
	}

	return pcrs, nil
}

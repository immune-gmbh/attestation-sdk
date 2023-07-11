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
package types

import (
	"context"
	"crypto/sha512"
	"database/sql/driver"
	"encoding/hex"
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/pkg/measurements"
	"github.com/immune-gmbh/attestation-sdk/pkg/objhash"
	"github.com/immune-gmbh/attestation-sdk/pkg/uefi"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"lukechampine.com/blake3"
)

// HashValue represents a hashed value in the binary form.
type HashValue []byte

type hashID uint8

// noinspection GoSnakeCaseUsage
const (
	hashUndefined = hashID(iota)

	// HashAlgSHA2_512 requests to use SHA2-512 function
	HashAlgSHA2_512

	// HashAlgBlake3_512 requests to use Blake3-512 function
	HashAlgBlake3_512
)

func stableImageHash1024(firmwareImage *uefi.UEFI) ([]byte, error) {
	biosImg := biosimage.NewFromParsed(firmwareImage)
	bootProcess := measurements.SimulateBootProcess(
		context.Background(),
		biosImg,
		registers.Registers{
			registers.ACMPolicyStatus(0),
		},
		flows.Root,
	)
	if err := bootProcess.Log.Error(); err != nil {
		return nil, fmt.Errorf("unable to simulate boot process: %w", err)
	}
	resultState := bootProcess.CurrentState
	refs := resultState.MeasuredData.References().BySystemArtifact(biosImg)
	err := refs.Resolve()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve references: %w", err)
	}

	ranges := refs.Ranges()
	ranges.SortAndMerge()
	stableFWBytes := ranges.Compile(biosImg.Content)

	result, err := objhash.Build(ranges, stableFWBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to hash the stable firmware data: %w", err)
	}

	return result[:], nil
}

// NewImageStableHash constructs an ImageStableHash for an image.
func NewImageStableHash(
	firmwareImage *uefi.UEFI,
) (HashValue, error) {
	return stableImageHash1024(firmwareImage)
}

// NewImageStableHashFromImage constructs an ImageStableHash for an image.
//
// TODO: Parallelize calculation.
func NewImageStableHashFromImage(
	firmwareImage []byte,
) (HashValue, error) {
	if len(firmwareImage) < 32 {
		return nil, fmt.Errorf("image is too small")
	}
	parsedImage, err := uefi.Parse(firmwareImage, false)
	if err != nil {
		return nil, fmt.Errorf("unable to parse image: %w", err)
	}
	return NewImageStableHash(parsedImage)
}

// Hash returns a hash-value for the passed data and using specified hash-function.
func Hash(id hashID, data []byte) HashValue {
	switch id {
	case HashAlgSHA2_512:
		hashedValue := sha512.Sum512(data)
		return hashedValue[:]
	case HashAlgBlake3_512:
		hashedValue := blake3.Sum512(data)
		return hashedValue[:]
	default:
		panic(fmt.Sprintf("unknown id: %v", id))
	}
}

// Scan implements the Scanner interface for sql.
func (h *HashValue) Scan(value any) error {
	if value == nil {
		*h = HashValue(nil)
		return nil
	}

	src, ok := value.([]byte)

	if !ok {
		return fmt.Errorf("unknown value type: '%T'", value)
	}

	*h = make([]byte, len(src))
	copy(*h, src)

	return nil
}

// String implements fmt.Stringer.
func (h HashValue) String() string {
	return hex.EncodeToString(h[:])
}

// Value implements the driver sql.Valuer interface.
func (h HashValue) Value() (driver.Value, error) {
	return []byte(h), nil
}

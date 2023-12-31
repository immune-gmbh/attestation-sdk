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
	"bytes"
	"crypto/sha512"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"sync"

	"lukechampine.com/blake3"
)

const blake3Size = 512 / 8

// ImageID is an unique content-based ID of an image.
// See also: https://en.wikipedia.org/wiki/Content-addressable_storage
//
// If you change this type, then you can modify and use fbcode/scripts/xaionaro/migrate_fas_0/main.go
// to perform the migration.
type ImageID [sha512.Size + blake3Size]byte

var (
	_ json.Marshaler   = (*ImageID)(nil)
	_ json.Unmarshaler = (*ImageID)(nil)
	_ driver.Valuer    = (*ImageID)(nil)
	_ sql.Scanner      = (*ImageID)(nil)
	_ flag.Value       = (*ImageID)(nil)
)

// NewImageIDFromImage calculates an ImageID based on image content.
func NewImageIDFromImage(image []byte) ImageID {
	var wg sync.WaitGroup
	var hash0, hash1 [64]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		hash0 = sha512.Sum512(image)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		hash1 = blake3.Sum512(image)
	}()
	wg.Wait()

	var result ImageID
	if len(hash0)+len(hash1) != len(result) {
		panic(fmt.Errorf("%d + %d != %d", len(hash0), len(hash1), len(result)))
	}
	copy(result[:], hash0[:])
	copy(result[len(hash0):], hash1[:])
	return result
}

// NewImageIDFromBytes just converts type []byte to ImageID.
func NewImageIDFromBytes(imageID []byte) ImageID {
	var result ImageID
	if len(imageID) != len(result) {
		panic(fmt.Errorf("invalid length: %d != %d", len(imageID), len(result)))
	}
	copy(result[:], imageID)
	return result
}

// MarshalJSON implements json.Marshaler.
func (imgID ImageID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(imgID[:]) + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (imgID *ImageID) UnmarshalJSON(b []byte) error {
	expectedJSONLength := len(ImageID{})*2 + len(`""`)
	if len(b) != expectedJSONLength {
		return fmt.Errorf("invalid length: %d != %d: <%s>", len(b), expectedJSONLength, b)
	}
	if b[0] != '"' || b[len(b)-1] != '"' {
		return fmt.Errorf(`expected a string, which should be in quotes ("), but received: %s`, b)
	}
	s := string(b[1 : len(b)-1])
	v, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("expected hex, but received: %s", s)
	}
	copy((*imgID)[:], v)
	return nil
}

// Set implements flag.Value.
func (imgID *ImageID) Set(in string) error {
	in = strings.TrimPrefix(in, "0x")

	v, err := hex.DecodeString(in)
	if err != nil {
		return err
	}

	if len(v) != len(*imgID) {
		return fmt.Errorf("the length is invalid; expected:%d, got:%d", len(*imgID), len(v))
	}
	copy((*imgID)[:], v)
	return nil
}

// String implements fmt.Stringer.
func (imgID ImageID) String() string {
	return hex.EncodeToString(imgID[:])
}

// GoString implements fmt.GoStringer.
func (imgID ImageID) GoString() string {
	return hex.EncodeToString(imgID[:])
}

// BlobStorageKey returns the path should be used to store this image.
func (imgID ImageID) BlobStorageKey() []byte {
	return imgID[:]
}

// IsZero returns true if ImageID contains the zero value.
func (imgID ImageID) IsZero() bool {
	emptyImageID := ImageID{}
	return bytes.Equal(imgID[:], emptyImageID[:])
}

// Value converts the value to be stored in DB.
func (imgID ImageID) Value() (driver.Value, error) {
	if imgID.IsZero() {
		return nil, nil
	}
	return imgID[:], nil
}

// Scan converts DB's value to ImageID.
func (imgID *ImageID) Scan(srcI any) error {
	if srcI == nil {
		*imgID = ImageID{}
		return nil
	}

	src, ok := srcI.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, received %T", srcI)
	}

	if len(src) != len(*imgID) {
		return fmt.Errorf("expected length %d, received %d", len(*imgID), len(src))
	}

	copy((*imgID)[:], src)
	return nil
}

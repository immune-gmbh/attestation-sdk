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
package imgalign

import (
	"fmt"
)

// ErrNoOrigImageToCompareWith is returned on attempt to make a diff
// report if nil original image.
type ErrNoOrigImageToCompareWith struct{}

func (ErrNoOrigImageToCompareWith) Error() string {
	return "no original image to compare with"
}

// ErrImageLengthDoesNotMatch is returned when the size of the UEFI image
// is not as expected.
type ErrImageLengthDoesNotMatch struct {
	ExpectedLength uint
	ReceivedLength uint
}

func (err ErrImageLengthDoesNotMatch) Error() string {
	return fmt.Sprintf("images length does not match: %d != %d", err.ReceivedLength, err.ExpectedLength)
}

// ErrUnableToFindBIOSRegion is returned if BIOSRegion is not found
type ErrUnableToFindBIOSRegion struct {
	Err error
}

func (err ErrUnableToFindBIOSRegion) Error() string {
	return fmt.Sprintf("unable to find BIOS region: %v", err.Err)
}

func (err ErrUnableToFindBIOSRegion) Unwrap() error {
	return err.Err
}

// ErrUnexpectedAmountOfBIOSRegions is returned when an UEFI image
// contains an amount of BIOS regions not equals to one.
type ErrUnexpectedAmountOfBIOSRegions struct {
	FoundCount uint
}

func (err ErrUnexpectedAmountOfBIOSRegions) Error() string {
	return fmt.Sprintf("expected amount of BIOS regions is one, but found: %d", err.FoundCount)
}

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

package intelacm

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm/report/generated/intelacmanalysis"
)

// GetACMInfo tries to parse ACM information from a firmware image
func GetACMInfo(image []byte) (*intelacmanalysis.ACMInfo, error) {
	entries, err := fit.GetEntries(image)
	if err != nil {
		return nil, ErrParsingFITEntries{err: err}
	}

	acmInfo, _, err := findACM(entries)
	if err != nil {
		return nil, err
	}

	result := &intelacmanalysis.ACMInfo{
		Date:   int32(acmInfo.GetDate()),
		SESVN:  int16(acmInfo.GetSESVN()),
		TXTSVN: int16(acmInfo.GetTXTSVN()),
	}

	// Signature verification is blocked by:
	// https://premiersupport.intel.com/IPS/5003b00001cnlpi
	// (and further NDAs needs to be lifted)
	//result.SignatureIsValid = acmInfo.VerifySignature()
	return result, err
}

func findACM(fitEntries []fit.Entry) (*fit.EntrySACMData, *fit.EntrySACM, error) {
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntrySACM:
			acmData, err := fitEntry.ParseData()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse ACM, err: %v", err)
			}
			return acmData, fitEntry, nil
		}
	}
	return nil, nil, &ErrNoSACMFound{}
}

// ErrParsingFITEntries means that an error happened when trying to get FIT entries
type ErrParsingFITEntries struct {
	err error
}

func (e ErrParsingFITEntries) Error() string {
	return fmt.Sprintf("failed to parse FIT entries: %v", e.err)
}

// ErrNoSACMFound means that "Startup AC Module" entry was not found
type ErrNoSACMFound struct{}

func (e ErrNoSACMFound) Error() string {
	return "Startup AC Module entry is not found in FIT"
}

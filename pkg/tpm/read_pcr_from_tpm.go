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
	"fmt"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/marcoguerri/go-tpm-tcti/abrmd"
)

// ReadPCRFromTPM reads PCR value from TPM.
func ReadPCRFromTPM(pcrIndex pcrtypes.ID, alg tpm2.Algorithm) ([]byte, error) {
	if pcrIndex >= amountOfPCRs {
		return nil, fmt.Errorf("invalid PCR index: %d (should be less than %d)", pcrIndex, amountOfPCRs)
	}

	var mErr errors.MultiError

	// Try to read PCR values from sysfs
	if pcrsData, err := os.ReadFile(tpm12PCRsPath); err == nil {
		if pcrs, err := parseSysfsPCRs(pcrsData); err == nil {
			return pcrs[pcrIndex], nil
		}
		mErr.Add(fmt.Errorf("unable to parse %s: %w", tpm12PCRsPath, err))
	} else {
		mErr.Add(fmt.Errorf("unable to read %s: %w", tpm12PCRsPath, err))
	}

	// Try abrmd first, if failure then try /dev/tpm{rm,}.
	abrmdClient, err := abrmd.NewBroker()
	if err == nil {
		defer abrmdClient.Close()
		// abrmd is part of TPM2 tools, therefore we support on TPM2.0 here.
		// If we have TPM1.2 then abrmdClient won't initialize.
		pcrValue, err := tpm2.ReadPCR(abrmdClient, int(pcrIndex), alg)
		if err != nil {
			mErr.Add(fmt.Errorf("unable to get PCR0 value through abrmd: %w", err))
			return nil, mErr.ReturnValue()
		}
		return pcrValue, nil
	}
	mErr.Add(fmt.Errorf("unable to connect to abrmd: %w", err))

	// No success with abrmd, trying /dev/tpm{rm,}:
	tpm, err := hwapi.NewTPM()
	if err != nil {
		mErr.Add(fmt.Errorf("unable to open TPM: %w", err))
		return nil, mErr.ReturnValue()
	}
	defer tpm.Close()

	// There's method tpm.ReadPCR, but we cannot use it because it does
	// not allow to pick the hashing algorithm.
	var pcrValue []byte
	switch tpm.Version {
	case hwapi.TPMVersion12:
		pcrValue, err = tpm1.ReadPCR(tpm.RWC, uint32(pcrIndex))
	case hwapi.TPMVersion20:
		pcrValue, err = tpm2.ReadPCR(tpm.RWC, int(pcrIndex), alg)
	default:
		mErr.Add(fmt.Errorf("unsupported TPM version: %x", tpm.Version))
		return nil, mErr.ReturnValue()
	}

	if err != nil {
		mErr.Add(fmt.Errorf("uanble to get PCR0 value directly from TPM: %w", err))
		return nil, mErr.ReturnValue()
	}

	return pcrValue, nil
}

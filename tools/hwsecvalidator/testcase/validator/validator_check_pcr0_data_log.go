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
package validator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/immune-gmbh/attestation-sdk/pkg/xtpmeventlog"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/biosconds/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
)

// PCR0DATALog checks if TPM EventLog contains expected granular log for PCR0_DATA (CBnT).
type PCR0DATALog struct{}

// Validate implements Validator.
func (PCR0DATALog) Validate(
	ctx context.Context,
	info *ValidationInfo,
) error {
	log := logger.FromCtx(ctx)

	if info.EventLog == nil {
		// We lose eventlog when do kexec in YARD, and this is not a fault
		// of a vendor or NPIs, so no sense to return a validation error here.
		// Just printing a warning and continuing.
		//
		// See also: https://www.internalfb.com/tasks?t=98458790
		log.Warnf("no EventLog, cannot validate it")
		return nil
	}

	if (intelconds.BPMPresent{}).Check(ctx, info.ExpectedBootResult.CurrentState) {
		log.Debugf("is not a CBnT platform, skipping validation")
		return nil
	}

	for _, hashAlgo := range []tpmeventlog.TPMAlgorithm{tpmeventlog.TPMAlgorithmSHA1, tpmeventlog.TPMAlgorithmSHA256} {
		pcr0Data, pcr0DataDigest, err := xtpmeventlog.ExtractPCR0DATALog(info.EventLog, hashAlgo)
		if errors.As(err, &xtpmeventlog.ErrPCR0DataLogTooSmall{}) {
			// it means we have the description of the old formwat, which just does not contain
			// machine-readable explanation of the PCR0_DATA content.
			log.Warnf("no extended PCR0_DATA log entry, cannot validate it: err:%v", err)
			continue
		}
		if err != nil {
			return ErrIncorrectEventLog{
				Err: ErrWrongPCR0DATALog{
					Algo: hashAlgo,
					Err: ErrParsePCR0DATALog{
						Err: err,
					},
				},
			}
		}

		pcr0DataMeasurement, err := pcr0Data.Measurement(cbnt.Algorithm(hashAlgo))
		if err != nil {
			return ErrIncorrectEventLog{
				Err: ErrWrongPCR0DATALog{
					Algo:   hashAlgo,
					Logged: pcr0Data,
					Err: ErrCompilePCR0DATAMeasurement{
						PCR0Data: pcr0Data,
						HashAlgo: hashAlgo,
						Err:      err,
					},
				},
			}
		}
		pcr0DataBytes := pcr0DataMeasurement.CompileMeasurableData(info.FirmwareCurrent.UEFI.Buf())
		hashHandler, err := hashAlgo.Hash()
		if err != nil {
			panic(fmt.Errorf("internal error: invalid hash algo: %v", hashAlgo))
		}
		hasher := hashHandler.New()
		hasher.Write(pcr0DataBytes)
		pcr0DataDigestReconstructed := hasher.Sum(nil)
		if !bytes.Equal(pcr0DataDigest, pcr0DataDigestReconstructed) {
			return ErrIncorrectEventLog{
				Err: ErrWrongPCR0DATALog{
					Algo:   hashAlgo,
					Logged: pcr0Data,
					Err: ErrReconstructDigestMismatch{
						PCR0Data: pcr0Data,
						HashAlgo: hashAlgo,
						Expected: pcr0DataDigest,
						Actual:   pcr0DataDigestReconstructed,
					},
				},
			}
		}

		origPCR0 := pcr0Data.OriginalPCR0ForHash(cbnt.Algorithm(hashAlgo))
		initialValue := make([]byte, hasher.Size())
		initialValue[len(initialValue)-1] = 3 // TPM locality is 3
		expectedPCR0Bank := hashHandler.New()
		expectedPCR0Bank.Write(initialValue)
		expectedPCR0Bank.Write(pcr0DataDigest)
		origPCR0Expected := expectedPCR0Bank.Sum(nil)

		if !bytes.Equal(origPCR0, origPCR0Expected) {
			return ErrIncorrectEventLog{
				Err: ErrWrongPCR0DATALog{
					Algo:   hashAlgo,
					Logged: pcr0Data,
					Err: ErrOriginalPCR0{
						HashAlgo: hashAlgo,
						Expected: origPCR0Expected,
						Actual:   origPCR0,
					},
				},
			}
		}
	}

	return nil
}

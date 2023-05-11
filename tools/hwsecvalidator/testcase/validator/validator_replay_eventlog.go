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
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// ReplayEventLog checks if current PCR0 values could be reproduces by replaying
// the EventLog.
type ReplayEventLog struct{}

// Validate implements Validator.
func (ReplayEventLog) Validate(
	ctx context.Context,
	info *ValidationInfo,
) error {
	if info.EventLog == nil {
		// We lose eventlog when do kexec in YARD, and this is not a fault
		// of a vendor or NPIs, so no sense to return a validation error here.
		// Just printing a warning and continuing.
		//
		// See also: https://www.internalfb.com/tasks?t=98458790
		logger.FromCtx(ctx).Warnf("no EventLog, cannot validate it")
		return nil
	}

	for _, alg := range info.ExpectedTPMState.SupportedAlgos {
		logger.FromCtx(ctx).Tracef("replaying TPM EventLog for algorithm %s", alg)
		pcr0Expected, err := info.ExpectedTPMState.PCRValues.Get(0, alg)
		if err != nil {
			return ErrGetPCR0Measurements{fmt.Errorf("unable to obtain expected PCR0 value: %w", err)}
		}

		var replayLog bytes.Buffer
		pcr0Replayed, err := tpmeventlog.Replay(info.EventLog, 0, alg, &replayLog)
		if err != nil {
			return ErrReplayEventLog{Err: fmt.Errorf("unable to replay PCR0 value for algo %d: %w", alg, err)}
		}
		pcr0Current := info.PCR0Current[alg]

		if !bytes.Equal(pcr0Replayed, pcr0Current) {
			var measurementsLog string
			if !bytes.Equal(pcr0Current, pcr0Expected) {
				measurementsLog = info.ExpectedBootResult.CurrentState.MeasuredData.String()
			}

			return ErrReplayEventLog{
				Algo:            alg,
				MeasurementsLog: measurementsLog,
				ReplayLog:       replayLog.String(),
				Err:             ErrPCR0Mismatch{Received: pcr0Replayed, Expected: pcr0Current},
			}
		}
	}

	return nil
}

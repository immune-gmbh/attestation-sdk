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

package validator

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// CurrentKMID validates if KMID of ACM_POLICY_STATUS matched the KMID of Key Manifest.
type CurrentKMID struct{}

// Validate implements Validator.
func (CurrentKMID) Validate(
	ctx context.Context,
	info *ValidationInfo,
) error {
	if info.FirmwareCurrent.Intel == nil {
		logger.FromCtx(ctx).Debugf("not an Intel firmware, skipping validation")
		return nil
	}

	currentKMID := info.StatusRegisters.Find(registers.AcmPolicyStatusRegisterID).(registers.ACMPolicyStatus).KMID()
	if info.FirmwareCurrent.Intel.KM.KMID != currentKMID {
		return ErrKMIDMismatch{
			Actual:   currentKMID,
			Expected: info.FirmwareCurrent.Intel.KM.KMID,
		}
	}

	return nil
}

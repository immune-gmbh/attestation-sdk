package validator

import (
	"context"
)

// ExpectHostBootedUp validates that the host is booted or not
type ExpectHostBootedUp struct {
	expectedToBoot bool
}

// Validate implements Validator.
func (hb ExpectHostBootedUp) Validate(
	ctx context.Context,
	info *ValidationInfo,
) error {
	if info.HostBooted != hb.expectedToBoot {
		if hb.expectedToBoot {
			return ErrHostFailedBootUp{}
		}
		return ErrHostBootedUp{}
	}
	return nil
}

// NewExpectHostBootedUp creates a new HostBootedValidator validator
func NewExpectHostBootedUp(expectedToBoot bool) ExpectHostBootedUp {
	return ExpectHostBootedUp{
		expectedToBoot: expectedToBoot,
	}
}

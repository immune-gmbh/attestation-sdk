package validator

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
)

// Validator is a validation handler of a single feature.
type Validator interface {
	// Validate returns nil if the feature works properly, and non-nil if
	// there is an problem.
	Validate(ctx context.Context, info *ValidationInfo) error
}

// Validators is a set of Validator-s.
type Validators []Validator

// Validate just calls Validate methods of each Validator until first error
// received. If no error received, then nil is returned.
func (s Validators) Validate(ctx context.Context, info *ValidationInfo) error {
	mErr := &errors.MultiError{}
	for _, validator := range s {
		if err := validator.Validate(ctx, info); err != nil {
			mErr.Add(ErrValidator{Err: err, Validator: validator})
		}
	}
	return mErr.ReturnValue()
}

// CommonHostBootUpExpected is a set of Validator-s which are expected to be executed for any
// test case that expects the host to boot up
func CommonHostBootUpExpected() Validators {
	return Validators{
		NewExpectHostBootedUp(true),
		ExpectedFirmware{},
		ExpectedPCR0{},
		ReplayEventLog{},
		CurrentKMID{},
		PCR0DATALog{},
	}
}

// CommonHostBootUpNotExpected is a set of Validator-s which are expected to be executed for any
// test case that doesn't expect the host to boot up
func CommonHostBootUpNotExpected(extraValidators ...Validator) Validators {
	result := Validators{
		NewExpectHostBootedUp(false),
	}
	for _, validator := range extraValidators {
		result = append(result, validator)
	}
	return result
}

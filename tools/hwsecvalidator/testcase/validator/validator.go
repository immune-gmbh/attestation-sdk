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

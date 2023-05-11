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
	"fmt"
	"regexp"
)

// ExpectSEL validates that SEL events contain the expected one
type ExpectSEL struct {
	positiveMatcher *regexp.Regexp
	negativeMatcher *regexp.Regexp
}

// Validate implements Validator.
func (es ExpectSEL) Validate(
	ctx context.Context,
	info *ValidationInfo,
) error {
	// SELs should be sorted by timestamp
	for i := len(info.SELs) - 1; i >= 0; i-- {
		if es.positiveMatcher != nil && es.positiveMatcher.MatchString(info.SELs[i].Message) {
			return nil
		}
		if es.negativeMatcher != nil && es.negativeMatcher.MatchString(info.SELs[i].Message) {
			return ErrUnexepectedSELFound{matchExpression: es.negativeMatcher.String()}
		}
	}

	if es.positiveMatcher != nil {
		return ErrSELNotFound{matchExpression: es.positiveMatcher.String()}
	}
	return nil
}

// NewExpectSEL creates new matcher for a SEL event
// @positive is an optional SEL event should be found among all SELs
// @negative is an optional SEL event that should not be found before the positive SEL is found. If positive SEL is not specified,
// negative should not match any SEL event
func NewExpectSEL(positive string, negatve string) (ExpectSEL, error) {
	if len(positive) == 0 && len(negatve) == 0 {
		return ExpectSEL{}, fmt.Errorf("either positive or negative SEL events matching expression should be provided")
	}

	var positiveMatcher, negativeMatcher *regexp.Regexp
	var err error

	if len(positive) > 0 {
		positiveMatcher, err = regexp.Compile(positive)
		if err != nil {
			return ExpectSEL{}, fmt.Errorf("failed to compile '%s': %w", positive, err)
		}
	}

	if len(negatve) > 0 {
		negativeMatcher, err = regexp.Compile(negatve)
		if err != nil {
			return ExpectSEL{}, fmt.Errorf("failed to compile '%s': %w", negatve, err)
		}
	}

	return ExpectSEL{
		positiveMatcher: positiveMatcher,
		negativeMatcher: negativeMatcher,
	}, nil
}

// MustExpectSEL creates a new ExpectSEL validator and panics if an error occures
func MustExpectSEL(positive string, negatve string) ExpectSEL {
	result, err := NewExpectSEL(positive, negatve)
	if err != nil {
		panic(err)
	}
	return result
}

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

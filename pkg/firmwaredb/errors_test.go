package rtpdb

import (
	"errors"
	"testing"
)

var (
	allErrors = []error{
		ErrInitMySQL{},
		ErrMySQLPing{},
		ErrParseModelIDs{},
		ErrCancelled{},
	}
)

func TestErrors(t *testing.T) {
	for _, err := range allErrors {
		// Check if Error will panic
		_ = err.Error()

		// Check if Unwrap will panic
		_ = errors.Unwrap(err)
	}
}

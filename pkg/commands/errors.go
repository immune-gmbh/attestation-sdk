package commands

import (
	"fmt"
)

// ExitCoder is an error signature used to override the exitcode in the end
// of main.main.
type ExitCoder interface {
	ExitCode() int
}

type ErrArgs struct {
	Err error
}

func (err ErrArgs) Error() string {
	return fmt.Sprintf("invalid arguments: %v", err.Err)
}

func (err ErrArgs) Unwrap() error {
	return err.Err
}

type SilentError struct {
	Err error
}

func (err SilentError) Error() string {
	return fmt.Sprintf("%v", err.Err)
}

func (err SilentError) Unwrap() error {
	return err.Err
}

// Descriptioner is the interface for error-s which requires method Description,
// which in turn is used to provide verbose explanation of how to interpret the
// error.
type Descriptioner interface {
	Description() string
}

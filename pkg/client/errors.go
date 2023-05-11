package client

import (
	"fmt"
)

type ErrRequestIsNil struct{}

func (err ErrRequestIsNil) Error() string {
	return "request is nil"
}

type ErrImageTooLarge struct {
	MaxSize      uint
	ReceivedSize uint
}

func (err ErrImageTooLarge) Error() string {
	return fmt.Sprintf("firmware image size is %d, while maximum allowed size is %d",
		err.ReceivedSize, err.MaxSize)
}

// ErrNoDestination means neither Endpoints nor SMC tier is set.
type ErrNoDestination struct{}

// Error implements interface "error"
func (err ErrNoDestination) Error() string {
	return "no destination is set"
}

// ErrEndpointsListEmpty means the Endpoints list is provided, but it is empty;
// most likely an internal error in the code. If there are no Endpoints then pass nil instead.
type ErrEndpointsListEmpty struct{}

// Error implements interface "error"
func (err ErrEndpointsListEmpty) Error() string {
	return "endpoints list is not nil, but empty"
}

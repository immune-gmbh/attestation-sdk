package firmwaredb

import (
	"fmt"
)

type Err[T fmt.Stringer] struct {
	Err         error
	Description T
}

func (err Err[T]) Error() string {
	var s T
	return fmt.Sprintf("%s: %v", s.String(), err.Err)
}

func (err Err[T]) Unwrap() error {
	return err.Err
}

type NotFound struct {
	Filters Filters
}

func (e NotFound) String() string {
	return fmt.Sprintf("nothing found using filters %s", e.Filters)
}

type ErrNotFound = Err[NotFound]

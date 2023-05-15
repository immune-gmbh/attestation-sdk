package rtpdb

import (
	"fmt"
)

// ErrInitMySQL implements "error", for the description see Error.
type ErrInitMySQL struct {
	Err error
}

func (err ErrInitMySQL) Error() string {
	return fmt.Sprintf("unable to initialize a MySQL client: %v", err.Err)
}

func (err ErrInitMySQL) Unwrap() error {
	return err.Err
}

// ErrMySQLPing implements "error", for the description see Error.
type ErrMySQLPing struct {
	Err error
}

func (err ErrMySQLPing) Error() string {
	return fmt.Sprintf("unable to ping the MySQL server: %v", err.Err)
}

func (err ErrMySQLPing) Unwrap() error {
	return err.Err
}

// ErrParseModelIDs implements "error", for the description see Error.
type ErrParseModelIDs struct {
	Err         error
	ModelFamily ModelFamily
}

func (err ErrParseModelIDs) Error() string {
	return fmt.Sprintf("unable to parse serialized model IDs '%s': %v",
		err.ModelFamily.ModelIDs, err.Err)
}

func (err ErrParseModelIDs) Unwrap() error {
	return err.Err
}

// ErrCancelled implements "error", for the description see Error.
type ErrCancelled struct {
	Err error
}

func (err ErrCancelled) Error() string {
	if err.Err != nil {
		return fmt.Sprintf("cancelled: %v", err.Err)
	}
	return "cancelled"
}

func (err ErrCancelled) Unwrap() error {
	return err.Err
}

package models

import (
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/xjson"
)

func init() {
	analysis.RegisterType((*SQLErrorWrapper)(nil))
	analysis.RegisterType((*GenericSQLError)(nil))
}

// GenericSQLError is used as the fallback type for an error,
// which type was not registered in the analysis type registry.
type GenericSQLError struct {
	Err string
}

// Error implements interface "error".
func (e GenericSQLError) Error() string {
	return e.Err
}

// SQLErrorWrapper wraps an error to serialize and deserialize it for SQL.
// The type is preserved if it was registered using analysis.RegisterType.
type SQLErrorWrapper struct {
	Err error
}

// Error implements interface "error".
func (e SQLErrorWrapper) Error() string {
	return e.Err.Error()
}

// Unwrap implements the interface used by errors.Unwrap()
func (e SQLErrorWrapper) Unwrap() error {
	return e.Err
}

// Value converts the value to be stored in DB.
func (e SQLErrorWrapper) Value() (driver.Value, error) {
	if e.Err == nil {
		return nil, nil
	}

	typeRegistry := analysis.TypeRegistry()
	b, err := xjson.MarshalWithTypeIDs(e, typeRegistry)
	if err != nil && errors.As(err, &analysis.ErrTypeIDNotRegistered{}) {
		// The error (or a wrapped error) is not serializable/deserializable.
		e.Err = GenericSQLError{Err: e.Err.Error()}
		b, err = xjson.MarshalWithTypeIDs(e, typeRegistry)
	}
	return string(b), err
}

// Scan converts DB's value to JobID.
func (e *SQLErrorWrapper) Scan(src any) error {
	if src == nil {
		e.Err = nil
		return nil
	}

	var b []byte
	switch v := src.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	default:
		return fmt.Errorf("expected string or []byte, but received %T", v)
	}

	typeRegistry := analysis.TypeRegistry()
	return xjson.UnmarshalWithTypeIDs(b, e, typeRegistry)
}

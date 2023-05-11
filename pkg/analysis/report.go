package analysis

import (
	"database/sql/driver"
	"fmt"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/xjson"
)

// Severity represents severity of an issue
type Severity uint32

const (
	// SeverityInfo tells that the issue is not important
	SeverityInfo Severity = iota

	// SeverityWarning tells that the issue has a medium priority
	SeverityWarning

	// SeverityCritical tells that the issue has a high priority
	SeverityCritical
)

// Issue describes a single found problem in firmware
type Issue struct {
	// Custom is a custom information provided for issue description. Should be serialisable
	Custom any

	// Severity tells how important is found issue
	Severity Severity

	// Description is a text description of a found problem
	Description string
}

// Report is an outcome of every firmware analysis algorithm
//
// TODO: consider using Go generics to specify the `Custom` field.
type Report struct {
	// Custom is a custom information provided for report description. Should be serialisable
	Custom any

	// Errors is the list of errors.
	Issues []Issue

	// Comments is the list of additional messages, which are not considered errors.
	Comments []string
}

// MarshalJSON implements json.Marshaler
func (r Report) MarshalJSON() ([]byte, error) {
	return xjson.MarshalWithTypeIDs(r, typeRegistry)
}

// UnmarshalJSON implements json.Unmarshaler
func (r *Report) UnmarshalJSON(b []byte) error {
	return xjson.UnmarshalWithTypeIDs(b, r, typeRegistry)
}

// Scan implements database/sql.Scanner
// TODO: remove this from this package. Package `analysis` should be agnostic of this stuff.
func (r *Report) Scan(src any) error {
	var b []byte
	switch src := src.(type) {
	case string:
		b = []byte(src)
	case []byte:
		b = src
	default:
		return fmt.Errorf("expected string or []byte, but received %T", src)
	}

	return r.UnmarshalJSON(b)
}

// Value implements database/sql/driver.Valuer
// TODO: remove this from this package. Package `analysis` should be agnostic of this stuff.
func (r *Report) Value() (driver.Value, error) {
	if r == nil {
		return nil, nil
	}

	b, err := r.MarshalJSON()
	return string(b), err
}

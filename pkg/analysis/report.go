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

package analysis

import (
	"database/sql/driver"
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/pkg/xjson"
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

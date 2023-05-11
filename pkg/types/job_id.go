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
package types

import (
	"bytes"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// JobID is an unique identifier of a job submitted to the server.
type JobID uuid.UUID

// NewJobID generates a new random JobID.
func NewJobID() JobID {
	return JobID(uuid.New())
}

// NewJobIDFromBytes contructs a JobID given its binary representation.
func NewJobIDFromBytes(b []byte) (JobID, error) {
	v, err := uuid.FromBytes(b)
	if err != nil {
		return JobID{}, err
	}
	return JobID(v), nil
}

// ParseJobID parses an UUID string as JobID.
func ParseJobID(s string) (JobID, error) {
	switch {
	case strings.HasPrefix(s, "0x") && len(s) == 34:
		b, err := hex.DecodeString(s[2:])
		if err != nil {
			return JobID{}, fmt.Errorf("unable to parse '%s' as hex: %w", s[2:], err)
		}
		return NewJobIDFromBytes(b)
	default:
		jobID, err := uuid.Parse(s)
		return JobID(jobID), err
	}
}

// String implements fmt.Stringer
func (jobID JobID) String() string {
	return uuid.UUID(jobID).String()
}

// Value converts the value to be stored in DB.
func (jobID JobID) Value() (driver.Value, error) {
	emptyJobID := JobID{}
	if bytes.Equal(jobID[:], emptyJobID[:]) {
		return nil, nil
	}
	return jobID[:], nil
}

// Scan converts DB's value to JobID.
func (jobID *JobID) Scan(srcI any) error {
	src, ok := srcI.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, received %T", srcI)
	}

	if len(src) != len(*jobID) {
		return fmt.Errorf("expected length %d, received %d", len(*jobID), len(src))
	}

	copy((*jobID)[:], src)
	return nil
}

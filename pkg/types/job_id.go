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
func (jobID *JobID) Scan(srcI interface{}) error {
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

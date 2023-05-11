package types

import (
	"context"
	"fmt"
	"strings"
)

// TestCase is a single test case.
type TestCase interface {
	// Setup modifies firmware in argument `image` in-memory to inject specifics
	// of the selected test case. This modified firmware should be flashed to
	// the test target. Then it is required to reboot the target.
	//
	// Setup does not really affect the system, it only returns an image,
	// which is expected to be written to the systems firmware storage unit.
	Setup(ctx context.Context, image []byte) error

	// Matches tells if given testcase should be executed for provided platform
	Matches(fwInfo FirmwareInfoProvider) bool

	// Validate returns nil if the target is in the expected state, or it
	// returns non-nil if a problem is found.
	Validate(ctx context.Context, origImage []byte, opts ...Option) error

	// Severity returns the level of harshness/seriousness of a test failure.
	Severity() Severity
}

// NameOf returns an unique name of a selected test case.
func NameOf(t TestCase) string {
	name := fmt.Sprintf("%T", t)
	// transform "*testCase.MyTestCase" to "MyTestCase"
	name = strings.TrimRight(strings.Split(name, ".")[1], "*")
	return name
}

// TestCases is a set of TestCase-s
type TestCases []TestCase

// Copy returns a copy of the map.
func (m TestCases) Copy() TestCases {
	r := make([]TestCase, 0, len(m))
	for _, v := range m {
		r = append(r, v)
	}
	return r
}

// Names returns names of the test cases.
func (m TestCases) Names() []string {
	r := make([]string, 0, len(m))
	for _, testCase := range m {
		r = append(r, NameOf(testCase))
	}
	return r
}

// Find returns the TestCase with the specified name. Returns nil if the
// TestCase is not found.
func (m TestCases) Find(name string) TestCase {
	for _, testCase := range m {
		if NameOf(testCase) == name {
			return testCase
		}
	}
	return nil
}

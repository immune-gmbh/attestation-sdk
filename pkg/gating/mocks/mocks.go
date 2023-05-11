package mocks

import (
	"github.com/stretchr/testify/mock"
)

// FakeGateChecker is a mock that implements GateChecker
type FakeGateChecker struct {
	mock.Mock
}

// NewFakeGateChecker makes a new mock gate checker
func NewFakeGateChecker() *FakeGateChecker {
	return &FakeGateChecker{}
}

// CheckHostname mocks the real one
func (c *FakeGateChecker) CheckHostname(gate string, hostname string) bool {
	args := c.Called(gate, hostname)
	return args.Get(0).(bool)
}

// CheckAssetID mocks the real one
func (c *FakeGateChecker) CheckAssetID(gate string, assetID int64) bool {
	args := c.Called(gate, assetID)
	return args.Get(0).(bool)
}

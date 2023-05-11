package gating

import (
	"siteopseng/go/gating"

	"github.com/facebookincubator/go-belt/tool/logger"
)

// GateChecker validates a sysprov/gating gate
type GateChecker interface {
	CheckHostname(gate string, hostname string) bool
	CheckAssetID(gate string, assetID int64) bool
}

type gateCheckerImpl struct {
	defaultValue bool
	log          logger.Logger
}

// NewGateChecker makes a new sysprov/gating gate checker
func NewGateChecker(defaultValue bool, log logger.Logger) GateChecker {
	return &gateCheckerImpl{defaultValue, log}
}

// CheckHostname checks if a given hostname passes the gate
func (c *gateCheckerImpl) CheckHostname(gate string, hostname string) bool {
	selector := gating.DeviceSelector{
		SelectBy:  gating.ByAssetName,
		AssetName: hostname,
	}
	return c.check(gate, selector)
}

// CheckAssetID checks if a given asset id passes the gate
func (c *gateCheckerImpl) CheckAssetID(gate string, assetID int64) bool {
	// TODO(aeh): check if this int32 is a problem
	selector := gating.DeviceSelector{
		SelectBy: gating.ByAssetID,
		AssetID:  int32(assetID),
	}
	return c.check(gate, selector)
}

func (c *gateCheckerImpl) check(gate string, selector gating.DeviceSelector) bool {
	ok, err := gating.CheckGating(gate, selector, nil)
	if err != nil {
		c.log.Errorf("error in checking gate sysprov/gating/%s (default: %v), error: %v", gate, c.defaultValue, err)
		return c.defaultValue
	}
	return ok
}

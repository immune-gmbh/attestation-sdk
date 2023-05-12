package devicegetter

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/device"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller"
)

// This is a dummy placeholder to replace code, which is specific to a company infra.
type DummyDeviceGetter struct{}

var _ controller.DeviceGetter = (*DummyDeviceGetter)(nil)

func (DummyDeviceGetter) GetDeviceByHostname(hostname string) (*device.Device, error) {
	return nil, fmt.Errorf("not implemented")
}
func (DummyDeviceGetter) GetDeviceByAssetID(assetID int64) (*device.Device, error) {
	return nil, fmt.Errorf("not implemented")
}

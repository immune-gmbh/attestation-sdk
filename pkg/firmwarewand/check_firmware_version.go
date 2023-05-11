package firmwarewand

import (
	"context"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
)

// CheckFirmwareVersion sends a firmware versions check request to AFAS
func (fwwand *FirmwareWand) CheckFirmwareVersion(
	ctx context.Context,
	firmwares []afas.FirmwareVersion,
) ([]bool, error) {
	var request afas.CheckFirmwareVersionRequest
	request.Firmwares = make([]*afas.FirmwareVersion, len(firmwares))
	for idx := range firmwares {
		request.Firmwares[idx] = &firmwares[idx]
	}
	response, err := fwwand.firmwareAnalyzer.CheckFirmwareVersion(&request)
	if err != nil {
		return nil, err
	}
	return response.ExistStatus, nil
}

package firmwarewand

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"
)

func (fwwand *FirmwareWand) Dump() ([]byte, error) {
	imageBytes, err := flashrom.Dump(fwwand.context, fwwand.flashromOptions...)
	if err != nil {
		return nil, err
	}

	return imageBytes, nil
}

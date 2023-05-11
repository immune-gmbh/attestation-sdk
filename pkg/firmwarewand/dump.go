package firmwarewand

import (
	"context"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flashrom"
)

func (fwwand *FirmwareWand) Dump(
	ctx context.Context,
) ([]byte, error) {
	imageBytes, err := flashrom.Dump(ctx, fwwand.flashromOptions...)
	if err != nil {
		return nil, err
	}

	return imageBytes, nil
}

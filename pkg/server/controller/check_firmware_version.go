package controller

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb"
)

// CheckFirmwareVersion checks
func (ctrl *Controller) CheckFirmwareVersion(
	ctx context.Context,
	checkedVersions []afas.FirmwareVersion,
) ([]bool, error) {
	log := logger.FromCtx(ctx)
	var versionsFilters firmwaredb.FiltersOR

	checked := make([]*firmwareVersionDate, len(checkedVersions))
	for _, firmwareVersion := range checkedVersions {
		versionsFilters = append(versionsFilters, firmwaredb.Filters{
			firmwaredb.FilterVersion(firmwareVersion.Version),
		})
	}

	firmwares, err := ctrl.OriginalFWDB.Get(ctx, versionsFilters)
	if err != nil {
		log.Errorf("Failed to get firmwares: %v", err)
		return nil, err
	}

	selectedVersionsDate := make(map[firmwareVersionDate]struct{})
	for _, fw := range firmwares {
		selectedVersionsDate[firmwareVersionDate{
			version: fw.Version,
		}] = struct{}{}
	}

	result := make([]bool, len(checkedVersions))
	for idx, checkedVersion := range checked {
		var found bool
		if checkedVersion != nil {
			_, found = selectedVersionsDate[*checkedVersion]
		}
		result[idx] = found
	}

	return result, nil
}

type firmwareVersionDate struct {
	version string
}

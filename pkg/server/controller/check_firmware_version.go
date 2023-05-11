package controller

import (
	"context"
	"time"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
)

// CheckFirmwareVersion checks
func (ctrl *Controller) CheckFirmwareVersion(
	ctx context.Context,
	checkedVersions []afas.FirmwareVersion,
) ([]bool, error) {
	log := logger.FromCtx(ctx)
	var versionsFilters rtpdb.FiltersOR

	checked := make([]*firmwareVersionDate, len(checkedVersions))
	for idx, firmwareVersion := range checkedVersions {
		date, err := models.ParseDate(firmwareVersion.Date)
		if err != nil {
			log.Errorf("unable to parse date '%s': %w", firmwareVersion.Date, err)
			continue
		}

		year, month, day := time.Time(date).UTC().Date()
		checked[idx] = &firmwareVersionDate{
			version: firmwareVersion.Version,
			year:    year,
			month:   month,
			day:     day,
		}

		versionsFilters = append(versionsFilters, rtpdb.Filters{
			rtpdb.FilterVersion(firmwareVersion.Version),
			rtpdb.FilterDate{Start: date, End: date},
		})
	}

	firmwares, err := ctrl.rtpDB.GetFirmwares(ctx, versionsFilters)
	if err != nil {
		log.Errorf("Failed to get firmwares: %v", err)
		return nil, err
	}

	selectedVersionsDate := make(map[firmwareVersionDate]struct{})
	for _, fw := range firmwares {
		year, month, day := time.Time(fw.GetDate()).UTC().Date()
		selectedVersionsDate[firmwareVersionDate{
			version: fw.FWVersion,
			year:    year,
			month:   month,
			day:     day,
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

	year  int
	month time.Month
	day   int
}

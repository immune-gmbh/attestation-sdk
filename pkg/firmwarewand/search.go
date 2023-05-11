package firmwarewand

import (
	"reflect"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"

	"github.com/facebookincubator/go-belt/tool/logger"
)

// Search asks the firmware analysis service to provide information on already
// collected images, which satisfies selected filters.
func (fwwand *FirmwareWand) Search(
	filters afas.SearchFirmwareFilters,
	shouldFetchContent bool,
) (*afas.SearchFirmwareResult_, error) {
	l := logger.FromCtx(fwwand.context)

	if reflect.ValueOf(filters).IsZero() {
		return nil, ErrInvalidInput{Desc: "filters cannot be completely empty"}
	}

	request := afas.SearchFirmwareRequest{
		FetchContent: shouldFetchContent,
	}
	request.OrFilters = append(request.OrFilters, &filters)

	l.Debugf("sending the request to firmware analyzer service...")
	result, err := fwwand.firmwareAnalyzer.SearchFirmware(&request)
	l.Debugf("received a response from the firmware analyzer service; err == %v, result == %+v", err, result)

	return result, err
}

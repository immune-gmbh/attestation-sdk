package firmwarewand

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
)

// SearchReport asks the firmware analysis service to provide information on already
// collected reports, which satisfies selected filters.
func (fwwand *FirmwareWand) SearchReport(
	filters afas.SearchReportFilters,
	limit uint64,
) (*afas.SearchReportResult_, error) {
	return fwwand.firmwareAnalyzer.SearchReport(&afas.SearchReportRequest{
		OrFilters: []*afas.SearchReportFilters{&filters},
		Limit:     int64(limit),
	})
}

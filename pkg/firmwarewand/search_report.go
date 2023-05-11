package firmwarewand

import (
	"context"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
)

// SearchReport asks the firmware analysis service to provide information on already
// collected reports, which satisfies selected filters.
func (fwwand *FirmwareWand) SearchReport(
	ctx context.Context,
	filters afas.SearchReportFilters,
	limit uint64,
) (*afas.SearchReportResult_, error) {
	return fwwand.afasClient.SearchReport(ctx, &afas.SearchReportRequest{
		OrFilters: []*afas.SearchReportFilters{&filters},
		Limit:     int64(limit),
	})
}

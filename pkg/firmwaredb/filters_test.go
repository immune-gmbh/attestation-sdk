package firmwaredb

import (
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb/models"
	"github.com/stretchr/testify/require"
)

func TestFiltersWhereCond(t *testing.T) {
	whereCond, args := Filters{
		FilterVersion("F20_3A15"),
		FilterNot{
			FilterTypes{models.FirmwareTypeBIOS},
		},
	}.WhereCond()

	require.Equal(t, "(`fw_version` = ?) AND (NOT ((`fw_date` = ? OR `firmware_date` BETWEEN ? AND ?) OR (qualification_status IN (4,0)) OR (1 == 0))) AND (firmware_type IN (1,21))", whereCond)
	require.Equal(t, []interface{}{"F20_3A15", "08/16/2017", int64(1502841600), int64(1502927999)}, args)
}

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

	require.Equal(t, "(`version` = ?) AND (NOT ((type IN (\"BIOS\"))))", whereCond)
	require.Equal(t, []any{"F20_3A15"}, args)
}

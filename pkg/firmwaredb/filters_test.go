package rtpdb

import (
	"testing"

	"privatecore/firmware/analyzer/if/rtp"
	"privatecore/firmware/analyzer/pkg/rtpdb/models"

	"github.com/stretchr/testify/require"
)

func TestFiltersWhereCond(t *testing.T) {
	date, err := models.ParseDate("08/16/2017")
	require.NoError(t, err)

	whereCond, args := Filters{
		FilterVersion("F20_3A15"),
		FilterNot{
			FilterDate{Start: date, End: date},
			FilterQualificationStatuses([]rtp.QualificationStatus{rtp.QualificationStatus_BAD, rtp.QualificationStatus_UNTESTED}),
			FilterQualificationStatuses{},
		},
		FilterTypes([]rtp.FirmwareType{rtp.FirmwareType_BIOS, rtp.FirmwareType_LinuxBoot}),
	}.WhereCond()

	require.Equal(t, "(`fw_version` = ?) AND (NOT ((`fw_date` = ? OR `firmware_date` BETWEEN ? AND ?) OR (qualification_status IN (4,0)) OR (1 == 0))) AND (firmware_type IN (1,21))", whereCond)
	require.Equal(t, []interface{}{"F20_3A15", "08/16/2017", int64(1502841600), int64(1502927999)}, args)
}

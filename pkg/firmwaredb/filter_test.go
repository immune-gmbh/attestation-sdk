package rtpdb

import (
	"privatecore/firmware/analyzer/if/rtp"
	"privatecore/firmware/analyzer/pkg/rtpdb/models"
	"privatecore/firmware/analyzer/pkg/types"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func mustParseDate(s string) models.Date {
	r, err := models.ParseDate(s)
	if err != nil {
		panic(err)
	}
	return r
}

func mustSerializeHash(hashes models.FirmwareHashes) models.FWHashSerialized {
	r, err := hashes.Serialize()
	if err != nil {
		panic(err)
	}
	return r
}

func TestFilterWhereCond(t *testing.T) {
	assertQuery := func(filter Filter, query string, args ...interface{}) {
		resultQuery, resultArgs := filter.WhereCond()
		assert.Equal(t, query, resultQuery)
		assert.Equal(t, args, resultArgs)
	}

	t.Run("FilterVersion", func(t *testing.T) {
		assertQuery(FilterVersion("some-version"), "`fw_version` = ?", "some-version")
	})

	t.Run("FilterDate", func(t *testing.T) {
		assertQuery(FilterDate{
			Start: mustParseDate("01/01/2021"),
			End:   mustParseDate("02/24/2022"),
		}, "`fw_date` != '' OR `firmware_date` BETWEEN ? AND ?", int64(1609459200), int64(1645747199))
		assertQuery(FilterDate{
			Start: mustParseDate("02/24/2022"),
			End:   mustParseDate("05/10/2022"),
		}, "`fw_date` LIKE ? OR `firmware_date` BETWEEN ? AND ?", "__/__/2022", int64(1645660800), int64(1652227199))
		assertQuery(FilterDate{
			Start: mustParseDate("02/23/2022"),
			End:   mustParseDate("02/24/2022"),
		}, "`fw_date` LIKE ? OR `firmware_date` BETWEEN ? AND ?", "02/__/2022", int64(1645574400), int64(1645747199))
		assertQuery(FilterDate{
			Start: mustParseDate("02/24/2022"),
			End:   mustParseDate("02/24/2022"),
		}, "`fw_date` = ? OR `firmware_date` BETWEEN ? AND ?", "02/24/2022", int64(1645660800), int64(1645747199))
	})

	t.Run("FilterTypes", func(t *testing.T) {
		assertQuery(FilterTypes{rtp.FirmwareType_BIOS, rtp.FirmwareType_BMC}, "firmware_type IN (1,2)")
	})

	t.Run("FilterEvaluationStatus", func(t *testing.T) {
		assertQuery(FilterEvaluationStatus(rtp.EvaluationStatus_EVT), "evaluation_status = ?", int64(2))
	})

	t.Run("FilterQualificationStatuses", func(t *testing.T) {
		assertQuery(FilterQualificationStatuses{rtp.QualificationStatus_UNTESTED, rtp.QualificationStatus_UNSCANNED}, "qualification_status IN (0,5)")
	})

	t.Run("FilterNot", func(t *testing.T) {
		assertQuery(FilterNot{filterTrue{}}, "NOT ((1 = 1))")
	})

	t.Run("FilterPCR0Tag", func(t *testing.T) {
		assertQuery(FilterPCR0Tag(2), "fw_hash LIKE ?", "%i:2;%")
	})

	t.Run("FilterIDs", func(t *testing.T) {
		assertQuery(FilterIDs{1, 2}, "id IN (1,2)")
	})
}

func TestFilterMatch(t *testing.T) {
	t.Run("FilterVersion", func(t *testing.T) {
		assert.True(t, FilterVersion("some-version").Match(&Firmware{
			FWVersion: "some-version",
		}))
		assert.False(t, FilterVersion("another-version").Match(&Firmware{
			FWVersion: "some-version",
		}))
	})

	t.Run("FilterDate", func(t *testing.T) {
		assert.True(t, FilterDate{
			Start: mustParseDate("01/01/2021"),
			End:   mustParseDate("02/24/2022"),
		}.Match(&Firmware{
			FirmwareDate: uint64(time.Date(2022, 2, 24, 5, 0, 0, 0, time.UTC).Unix()),
		}))
		assert.True(t, FilterDate{
			Start: mustParseDate("01/01/2021"),
			End:   mustParseDate("02/24/2022"),
		}.Match(&Firmware{
			FWDate: "02/24/2022",
		}))
		assert.False(t, FilterDate{
			Start: mustParseDate("01/01/2021"),
			End:   mustParseDate("02/24/2022"),
		}.Match(&Firmware{
			FirmwareDate: uint64(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix()),
		}))
		assert.False(t, FilterDate{
			Start: mustParseDate("01/01/2021"),
			End:   mustParseDate("02/24/2022"),
		}.Match(&Firmware{
			FWDate: "01/01/2020",
		}))
		assert.False(t, FilterDate{
			Start: mustParseDate("01/01/2021"),
			End:   mustParseDate("02/24/2022"),
		}.Match(&Firmware{
			FirmwareDate: uint64(time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC).Unix()),
		}))
		assert.False(t, FilterDate{
			Start: mustParseDate("01/01/2021"),
			End:   mustParseDate("02/24/2022"),
		}.Match(&Firmware{
			FWDate: "06/01/2022",
		}))
	})

	t.Run("FilterTypes", func(t *testing.T) {
		filter := FilterTypes{rtp.FirmwareType_BIOS, rtp.FirmwareType_BMC}
		assert.True(t, filter.Match(&Firmware{
			FirmwareType: rtp.FirmwareType_BIOS,
		}))
		assert.True(t, filter.Match(&Firmware{
			FirmwareType: rtp.FirmwareType_BMC,
		}))
		assert.False(t, filter.Match(&Firmware{
			FirmwareType: rtp.FirmwareType_LinuxBoot,
		}))
	})

	t.Run("FilterEvaluationStatus", func(t *testing.T) {
		assert.True(t, FilterEvaluationStatus(rtp.EvaluationStatus_EVT).Match(&Firmware{
			EvaluationStatus: rtp.EvaluationStatus_EVT,
		}))
		assert.False(t, FilterEvaluationStatus(rtp.EvaluationStatus_EVT).Match(&Firmware{
			EvaluationStatus: rtp.EvaluationStatus_DVT,
		}))
	})

	t.Run("FilterQualificationStatus", func(t *testing.T) {
		filter := FilterQualificationStatuses{rtp.QualificationStatus_UNTESTED, rtp.QualificationStatus_UNSCANNED}
		assert.True(t, filter.Match(&Firmware{
			QualificationStatus: rtp.QualificationStatus_UNTESTED,
		}))
		assert.True(t, filter.Match(&Firmware{
			QualificationStatus: rtp.QualificationStatus_UNSCANNED,
		}))
		assert.False(t, filter.Match(&Firmware{
			QualificationStatus: rtp.QualificationStatus_BAD,
		}))
	})

	t.Run("FilterNot", func(t *testing.T) {
		assert.True(t, FilterNot{filterFalse{}}.Match(&Firmware{}))
		assert.False(t, FilterNot{filterTrue{}}.Match(&Firmware{}))
		assert.False(t, FilterNot{filterFalse{}, filterTrue{}}.Match(&Firmware{}))
	})

	t.Run("FilterPCR0Tag", func(t *testing.T) {
		assert.True(t, FilterPCR0Tag(2).Match(&Firmware{
			FWHash: mustSerializeHash(models.FirmwareHashes{
				models.FirmwareHash{
					Tags: []types.TagID{1, 2, 3},
				},
			}),
		}))
		assert.False(t, FilterPCR0Tag(4).Match(&Firmware{
			FWHash: mustSerializeHash(models.FirmwareHashes{
				models.FirmwareHash{
					Tags: []types.TagID{1, 2, 3},
				},
			}),
		}))
	})

	t.Run("FilterIDs", func(t *testing.T) {
		filter := FilterIDs{1, 2}
		assert.True(t, filter.Match(&Firmware{
			ID: 1,
		}))
		assert.True(t, filter.Match(&Firmware{
			ID: 2,
		}))
		assert.False(t, filter.Match(&Firmware{
			ID: 3,
		}))
	})
}

type filterTrue struct{}

func (filterTrue) WhereCond() (string, []interface{}) {
	return "1 = 1", nil
}

func (filterTrue) Match(fw *Firmware) bool {
	return true
}

type filterFalse struct{}

func (filterFalse) WhereCond() (string, []interface{}) {
	return "1 = 0", nil
}

func (filterFalse) Match(fw *Firmware) bool {
	return false
}

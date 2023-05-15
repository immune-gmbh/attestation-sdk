package firmwaredb

import (
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb/models"
	"github.com/stretchr/testify/assert"
)

func TestFilterWhereCond(t *testing.T) {
	assertQuery := func(filter Filter, query string, args ...interface{}) {
		resultQuery, resultArgs := filter.WhereCond()
		assert.Equal(t, query, resultQuery)
		assert.Equal(t, args, resultArgs)
	}

	t.Run("FilterVersion", func(t *testing.T) {
		assertQuery(FilterVersion("some-version"), "`fw_version` = ?", "some-version")
	})

	t.Run("FilterTypes", func(t *testing.T) {
		assertQuery(FilterTypes{models.FirmwareTypeBIOS}, `firmware_type IN ("BIOS")`)
	})

	t.Run("FilterNot", func(t *testing.T) {
		assertQuery(FilterNot{filterTrue{}}, "NOT ((1 = 1))")
	})

	t.Run("FilterIDs", func(t *testing.T) {
		assertQuery(FilterIDs{1, 2}, "id IN (1,2)")
	})
}

func TestFilterMatch(t *testing.T) {
	t.Run("FilterVersion", func(t *testing.T) {
		assert.True(t, FilterVersion("some-version").Match(&Firmware{
			Version: "some-version",
		}))
		assert.False(t, FilterVersion("another-version").Match(&Firmware{
			Version: "some-version",
		}))
	})

	t.Run("FilterTypes", func(t *testing.T) {
		filter := FilterTypes{models.FirmwareTypeBIOS}
		assert.True(t, filter.Match(&Firmware{
			Type: models.FirmwareTypeBIOS,
		}))
	})

	t.Run("FilterNot", func(t *testing.T) {
		assert.True(t, FilterNot{filterFalse{}}.Match(&Firmware{}))
		assert.False(t, FilterNot{filterTrue{}}.Match(&Firmware{}))
		assert.False(t, FilterNot{filterFalse{}, filterTrue{}}.Match(&Firmware{}))
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

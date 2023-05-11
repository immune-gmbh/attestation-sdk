// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package firmwaredb

import (
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb/models"
	"github.com/stretchr/testify/assert"
)

func TestFilterWhereCond(t *testing.T) {
	assertQuery := func(filter Filter, query string, args ...any) {
		resultQuery, resultArgs := filter.WhereCond()
		assert.Equal(t, query, resultQuery)
		assert.Equal(t, args, resultArgs)
	}

	t.Run("FilterVersion", func(t *testing.T) {
		assertQuery(FilterVersion("some-version"), "`version` = ?", "some-version")
	})

	t.Run("FilterTypes", func(t *testing.T) {
		assertQuery(FilterTypes{models.FirmwareTypeBIOS}, `type IN ("BIOS")`)
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

func (filterTrue) WhereCond() (string, []any) {
	return "1 = 1", nil
}

func (filterTrue) Match(fw *Firmware) bool {
	return true
}

type filterFalse struct{}

func (filterFalse) WhereCond() (string, []any) {
	return "1 = 0", nil
}

func (filterFalse) Match(fw *Firmware) bool {
	return false
}

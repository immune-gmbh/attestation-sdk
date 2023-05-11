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
package validator

import (
	"context"
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/types"

	"github.com/stretchr/testify/require"
)

func TestExpectSELEvent(t *testing.T) {
	inputSELEvents := []types.SEL{
		{
			Timestamp: 100,
			Message:   "SEL Entry: FRU: 1, Record: Standard (0x02), Time: 2022-01-24 11:46:28, Sensor: PSB_STS (0x46), Event Data: (EE00FF) PSB Pass Assertion ",
		},
		{
			Timestamp: 200,
			Message:   "SEL Entry: FRU: 1, Record: Facebook Unified SEL (0xFB), GeneralInfo: POST(0x28), POST Failure Event: System PXE boot fail",
		},
		{
			Timestamp: 300,
			Message:   "SEL Entry: FRU: 1, Record: Standard (0x02), Time: 2022-01-26 07:13:29, Sensor: PSB_STS (0x46), Event Data: (EE7AFF) P0: BIOS RTM Signature verification failed Assertion ",
		},
	}

	t.Run("check_sel_found", func(t *testing.T) {
		validator, err := NewExpectSEL(".*PSB_STS.*BIOS RTM Signature verification failed.*", ".*PSB_STS.*PSB Pass Assertion.*")
		require.NoError(t, err)

		err = validator.Validate(context.Background(), &ValidationInfo{
			SELs: inputSELEvents,
		})
		require.NoError(t, err)
	})

	t.Run("check_sel_not_found", func(t *testing.T) {
		validator, err := NewExpectSEL(".*I don't know.*", "")
		require.NoError(t, err)

		err = validator.Validate(context.Background(), &ValidationInfo{
			SELs: inputSELEvents,
		})
		require.Error(t, err)
		require.ErrorAs(t, err, &ErrSELNotFound{})
		require.NotEmpty(t, err.Error())
	})
}

func TestNegativeEventHappenedLater(t *testing.T) {
	inputSELEvents := []types.SEL{
		{
			Timestamp: 100,
			Message:   "SEL Entry: FRU: 1, Record: Facebook Unified SEL (0xFB), GeneralInfo: POST(0x28), POST Failure Event: System PXE boot fail",
		},
		{
			Timestamp: 200,
			Message:   "SEL Entry: FRU: 1, Record: Standard (0x02), Time: 2022-01-26 07:13:29, Sensor: PSB_STS (0x46), Event Data: (EE7AFF) P0: BIOS RTM Signature verification failed Assertion ",
		},
		{
			Timestamp: 300,
			Message:   "SEL Entry: FRU: 1, Record: Standard (0x02), Time: 2022-01-26 07:46:28, Sensor: PSB_STS (0x46), Event Data: (EE00FF) PSB Pass Assertion ",
		},
	}

	validator, err := NewExpectSEL(".*PSB_STS.*BIOS RTM Signature verification failed.*", ".*PSB_STS.*PSB Pass Assertion.*")
	require.NoError(t, err)

	err = validator.Validate(context.Background(), &ValidationInfo{
		SELs: inputSELEvents,
	})
	require.Error(t, err)
	require.ErrorAs(t, err, &ErrUnexepectedSELFound{})
}

func TestExpectSELEventIncorrectRegularExpression(t *testing.T) {
	_, err := NewExpectSEL("[.", "")
	require.Error(t, err)

	_, err = NewExpectSEL("", "[.")
	require.Error(t, err)
}

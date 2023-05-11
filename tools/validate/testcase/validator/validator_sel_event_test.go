package validator

import (
	"context"
	"testing"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/validate/testcase/types"

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

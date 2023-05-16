package formatter

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestCompactText(t *testing.T) {
	t.Run("integer_field", func(t *testing.T) {
		b, err := (&CompactText{
			FieldAllowList: []string{"someIntegerField"},
		}).Format(&logrus.Entry{
			Time: time.Date(2001, 02, 03, 04, 05, 06, 07, time.UTC),
			Data: logrus.Fields{
				"someIntegerField": 1,
			},
			Level:   logrus.WarnLevel,
			Message: "msg",
		})
		require.NoError(t, err)
		require.Equal(t, "[2001-02-03T04:05:06Z W] msg\tsomeIntegerField=1\n", string(b))
	})
}

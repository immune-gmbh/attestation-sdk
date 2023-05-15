package firmwaredb

import (
	"context"
)

type DB interface {
	Get(ctx context.Context, filters ...Filter) ([]*Firmware, error)
}

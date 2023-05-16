package flashrom

import (
	"context"
	"time"
)

func (f *flashrom) dumpAfulnx64(ctx context.Context) ([]byte, error) {
	// We execute an external tool which add a lot of unpredictability,
	// for example it could hang for some reason. Therefore we use
	// a timeout.
	//
	// We expect AFULNX64 to handle the request within a minute, but
	// to be sure we wait up to 5 minutes.
	ctx, cancelFunc := context.WithTimeout(ctx, time.Minute*5)
	defer cancelFunc()

	return f.execReceive(ctx, f.Config.Afulnx64Path, outputPathArgument,
		// Save to file
		"/O",
		// Quiet and non-interactive
		"/Q",
	)
}

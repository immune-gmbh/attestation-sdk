package firmwarestorage

import (
	"context"
	"fmt"
	"time"

	"facebook/storage/everstore"
	"libfb/go/sr"
	"libfb/go/thriftbase"

	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// RemoveFirmwareFromEverstore remove the firmware image from Everstore.
func (storage *FirmwareStorage) RemoveFirmwareFromEverstore(
	ctx context.Context,
	everstoreHandle string,
) error {

	span, ctx := tracer.StartChildSpanFromCtx(ctx, "FirmwareStorageJob.RemoveFirmwareFromEverstore")
	defer span.Finish()

	conn, err := sr.GetClient(
		"dfsrouter.common",
		sr.Timeout(time.Minute),
		sr.ThriftOptions([]thriftbase.Option{thriftbase.Timeout(time.Minute)}),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize an everstore connection: %w", err)
	}

	everstoreClient := everstore.NewEverstoreClient(conn.Transport(), conn, conn)
	defer func() {
		if err := everstoreClient.Close(); err != nil {
			logger.FromCtx(ctx).Errorf("unable to close the client to Everstore: %v", err)
		}
	}()

	if err := everstoreClient.Remove(everstoreHandle, storage.callerName); err != nil {
		return fmt.Errorf("unable to remove the image from Everstore: %w", err)
	}
	return nil
}

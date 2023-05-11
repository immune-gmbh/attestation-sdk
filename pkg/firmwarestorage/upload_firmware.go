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

const (
	// fbtypeEverstoreFirmwareBinaries is the value of FBType "EVERSTORE_FIRMWARE_BINARIES"
	//
	// See https://www.internalfb.com/tao/fbtype/13895
	fbtypeEverstoreFirmwareBinaries = 13895
)

// UploadFirmwareToEverstore uploads a firmware image to Everstore and returns the Everstore handle
func (storage *FirmwareStorage) UploadFirmwareToEverstore(
	ctx context.Context,
	imageBytes []byte,
) (everstoreHandle string, err error) {

	span, ctx := tracer.StartChildSpanFromCtx(ctx, "FirmwareStorageJob.UploadFirmware")
	defer span.Finish()

	conn, err := sr.GetClient(
		"dfsrouter.common",
		sr.Timeout(time.Minute),
		sr.ThriftOptions([]thriftbase.Option{thriftbase.Timeout(time.Minute)}),
	)
	if err != nil {
		return "", fmt.Errorf("failed to initialize an everstore connection: %w", err)
	}

	everstoreClient := everstore.NewEverstoreClient(conn.Transport(), conn, conn)
	defer func() {
		if err := everstoreClient.Close(); err != nil {
			logger.FromCtx(ctx).Errorf("unable to close the client to Everstore: %v", err)
		}
	}()

	handle, err := everstoreClient.Write(imageBytes, fbtypeEverstoreFirmwareBinaries, "bin", storage.callerName)
	if err != nil {
		return "", fmt.Errorf("unable to write the image to Everstore: %w", err)
	}
	return handle, nil
}

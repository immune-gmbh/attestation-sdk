package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"

	"github.com/facebookincubator/go-belt/tool/logger"
	xlogrus "github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockManifold struct {
	storage sync.Map
}

func (m *mockManifold) Replace(path string, b []byte) (copied int64, err error) {
	time.Sleep(time.Second)
	m.storage.Store(path, b)
	return int64(len(b)), nil
}
func (m *mockManifold) Download(path string) (b []byte, err error) {
	if v, ok := m.storage.Load(path); ok {
		return v.([]byte), nil
	}
	return nil, fmt.Errorf("no such file: %s", path)
}
func (m *mockManifold) Close() error {
	return nil
}

func TestStorageInsertAndFind(t *testing.T) {
	xdbTier, release := createEphemeral(t)
	defer release()

	ctx := logger.CtxWithLogger(
		context.Background(),
		xlogrus.Default().WithLevel(logger.LevelDebug),
	)

	stor, err := NewStorage(
		xdbTier,
		&mockManifold{},
		nil,
		logger.FromCtx(ctx),
	)
	require.NoError(t, err)
	defer func() {
		err := stor.Close()
		require.NoError(t, err)
	}()
	stor.insertTriesLimit = 2

	t.Run("fully_specified_meta", func(t *testing.T) {
		data := []byte("unit-test-fully_specified_meta")

		meta := models.NewImageMetadata(data, "UNIT-TEST", "01/01/2001", "unit-test.txt")
		require.NoError(t, stor.Insert(ctx, meta, data))

		foundMetas, unlock, err := stor.Find(ctx, FindFilter{
			ImageID: &meta.ImageID,
		})
		require.NoError(t, err)
		require.NotNil(t, unlock)
		defer unlock()
		require.Len(t, foundMetas, 1)
		require.Equal(t, meta.ImageID, foundMetas[0].ImageID)
		require.Equal(t, meta.Filename, foundMetas[0].Filename)
		require.Equal(t, meta.FirmwareVersion, foundMetas[0].FirmwareVersion)
		require.Equal(t, meta.FirmwareDateString, foundMetas[0].FirmwareDateString)
	})

	t.Run("firmware_meta_not_specified", func(t *testing.T) {
		data := []byte("unit-test-firmware_meta_not_specified")

		meta := models.NewImageMetadata(data, "", "", "")
		require.NoError(t, stor.Insert(ctx, meta, data))

		foundMetas, unlock, err := stor.Find(ctx, FindFilter{
			ImageID: &meta.ImageID,
		})
		require.NoError(t, err)
		require.NotNil(t, unlock)
		defer unlock()

		require.Len(t, foundMetas, 1)
		require.Equal(t, meta.ImageID, foundMetas[0].ImageID)
		require.Empty(t, foundMetas[0].Filename)
		require.Empty(t, foundMetas[0].FirmwareVersion)
		require.Empty(t, foundMetas[0].FirmwareDateString)
	})
}

func TestStorageDuplicateHandling(t *testing.T) {
	xdbTier, release := createEphemeral(t)
	defer release()

	ctx := logger.CtxWithLogger(
		context.Background(),
		xlogrus.Default().WithLevel(logger.LevelDebug),
	)

	stor, err := NewStorage(
		xdbTier,
		&mockManifold{},
		nil,
		logger.FromCtx(ctx),
	)
	require.NoError(t, err)
	defer func() {
		err := stor.Close()
		require.NoError(t, err)
	}()
	stor.insertTriesLimit = 2

	data := []byte("unit-test")
	meta := models.NewImageMetadata(data, "unit-test.txt", "UNIT-TEST", "01/01/2001")

	// To avoid different values in test:
	//     require.Equal(t, meta.TSAdd.Unix(), gotMeta.TSAdd.Unix())
	//  below:
	meta.TSAdd = meta.TSAdd.Truncate(time.Second)

	errChan := make(chan error, 3)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		err := stor.Insert(ctx, meta, data)
		if err != nil {
			errChan <- err
		}
		wg.Done()
	}()
	go func() {
		err := stor.Insert(ctx, meta, data)
		if err != nil {
			errChan <- err
		}
		wg.Done()
	}()
	go func() {
		err := stor.Insert(ctx, meta, data)
		if err != nil {
			errChan <- err
		}
		wg.Done()
	}()
	wg.Wait()

	if !assert.Less(t, len(errChan), 3) {
		t.Errorf("errors are:\n%v\n%v\n%v", <-errChan, <-errChan, <-errChan)
		return
	}
	require.Len(t, errChan, 2)
	close(errChan)

	for err := range errChan {
		require.True(t, errors.As(err, &ErrAlreadyExists{}), fmt.Sprintf("%T:%v", err, err))
	}

	gotData, gotMeta, err := stor.Get(ctx, meta.ImageID)
	require.NoError(t, err)
	require.Equal(t, data, gotData)

	require.True(t, gotMeta.TSUpload.Valid)
	gotMeta.TSUpload = sql.NullTime{}

	require.Equal(t, meta.TSAdd.Unix(), gotMeta.TSAdd.Unix())
	gotMeta.TSAdd = meta.TSAdd

	require.Equal(t, meta, *gotMeta)

	err = stor.Insert(ctx, meta, data)
	require.True(t, errors.As(err, &ErrAlreadyExists{}), fmt.Sprintf("%T:%v", err, err))
}

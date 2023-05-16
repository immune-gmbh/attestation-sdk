// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/go-sql-driver/mysql"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/blobstorage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/spf13/pflag"
)

func main() {
	logLevel := logger.LevelDebug // the default value
	defaultDSN := (&mysql.Config{
		User:   os.Getenv("DBUSER"),
		Passwd: os.Getenv("DBPASS"),
		Net:    "tcp",
		Addr:   "127.0.0.1:3306",
		DBName: "afas",
	}).FormatDSN()
	rdbmsDriver := pflag.String("rdbms-driver-internal", "mysql", "")
	rdbmsDSN := pflag.String("rdbms-dsn-internal", defaultDSN, "")
	blobStorageURL := pflag.String("blob-storage-url", "fs:///srv/afasd", "")
	stage := pflag.String("stage", "create-new", "possible stages: create-new, delete-old-data, delete-old-metadata")
	pflag.Var(&logLevel, "log-level", "logging level")
	pflag.Parse()

	ctx := observability.WithBelt(context.Background(), logLevel, "", true)

	blobStoreClient, err := blobstorage.New(*blobStorageURL)
	if err != nil {
		logger.FromCtx(ctx).Panic(err)
	}

	stor, err := storage.New(*rdbmsDriver, *rdbmsDSN, blobStoreClient, nil, logger.FromCtx(ctx))
	if err != nil {
		logger.FromCtx(ctx).Panic(err)
	}

	switch *stage {
	case "create-new", "delete-old-data":
		_, columns, err := helpers.GetValuesAndColumns(models.FirmwareImageMetadata{}, nil)
		if err != nil {
			logger.FromCtx(ctx).Panic(err)
		}
		query := fmt.Sprintf("SELECT %s, image_id FROM firmware_image_metadata WHERE LENGTH(image_id) != ?", strings.Join(columns[1:], ","))
		args := []interface{}{len(types.ImageID{})}
		logger.FromCtx(ctx).Debugf("query:'%s', args:%v", query, args)

		rows, err := stor.DB.Query(
			query,
			args...,
		)
		if err != nil {
			logger.FromCtx(ctx).Panic(err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var oldImgID []byte
			var imgMeta models.FirmwareImageMetadata
			values, _, err := helpers.GetValuesAndColumns(imgMeta, nil)
			if err != nil {
				logger.FromCtx(ctx).Panic(err)
			}
			err = rows.Scan(append(values[1:], &oldImgID)...)
			if err != nil {
				logger.FromCtx(ctx).Panic(err)
			}

			// Old image ID combines SHA1 and SHA256.
			// New image ID combines SHA512 and Blake3-512.
			//
			// So we can just detect the old/new type by size:
			if len(oldImgID) == len(types.ImageID{}) {
				logger.FromCtx(ctx).Infof("ImageID %s is an already converted one, skipping the firmware", imgMeta.ImageID)
				continue
			}
			if imgMeta.HashStable != nil {
				logger.FromCtx(ctx).Panicf("ImageID %s is not a converted one, but HashStable is set (%s); this should never happen, please diagnose", imgMeta.ImageID, imgMeta.HashStable)
			}

			imgPath := hex.EncodeToString(oldImgID)

			if *stage == "create-new" {
				imgData, err := stor.GetFirmwareBytesByPath(ctx, imgPath)
				if err != nil {
					if strings.Contains(err.Error(), "CodedMessage:[404] Path not found") {
						logger.FromCtx(ctx).Warnf("unable to find image for old image ID %X", oldImgID)
						continue
					}
					logger.FromCtx(ctx).Panic(err)
				}

				imgMeta.ImageID = types.NewImageIDFromImage(imgData)
				imgMeta.HashStable, err = types.NewImageStableHashFromImage(imgData)
				if err != nil {
					logger.FromCtx(ctx).Warnf("unable to calculate HashStable for %s (old ID: %X): %v", imgMeta.ImageID, oldImgID, err)
				}
				err = stor.InsertFirmware(ctx, imgMeta, imgData)
				if err != nil {
					if errors.As(err, &storage.ErrAlreadyExists{}) {
						logger.FromCtx(ctx).Debugf("already exists: %s", imgMeta.ImageID)
					} else {
						panic(fmt.Errorf("unable to insert image with ID %s (old ID: %X): %v", imgMeta.ImageID, oldImgID, err))
					}
				} else {
					logger.FromCtx(ctx).Debugf("inserted: %s", imgMeta.ImageID)
				}
			}

			if *stage == "delete-old-data" {
				err = stor.BlobStorage.Delete(ctx, imgPath)
				if err != nil {
					logger.FromCtx(ctx).Panicf("unable to delete image with path '%s' (oldID: %X) from the blob storage bucket: %w",
						imgPath, oldImgID, err)
				}
				logger.FromCtx(ctx).Debugf("deleted for %X", oldImgID)
			}
		}
		if err := rows.Err(); err != nil {
			logger.FromCtx(ctx).Panic(err)
		}
	case "delete-old-metadata":
		result, err := stor.DB.Exec(
			"DELETE FROM firmware_image_metadata WHERE LENGTH(image_id) != ?",
			len(types.ImageID{}),
		)
		if err != nil {
			logger.FromCtx(ctx).Panic(err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			logger.FromCtx(ctx).Panic(err)
		}
		fmt.Println("rows deleted:", rowsAffected)
	}
}

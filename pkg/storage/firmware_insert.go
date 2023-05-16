package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"

	"github.com/go-sql-driver/mysql"
)

const (
	insertTriesLimit = 60
)

// If it was a MySQL error 1062 then it means the row with such
// PRIMARY KEY already exists and we want to return an appropriate error
// in this case.
func mySQLInsertError(insertedValue string, err error) error {
	if err == nil {
		return nil
	}
	if mysqlErr := asMySQLError(err, 1062); mysqlErr != nil {
		// MySQL error 1062 is used on duplicate error.
		return ErrAlreadyExists{insertedValue: insertedValue, Err: mysqlErr}
	}
	return ErrUnableToInsert{insertedValue: insertedValue, Err: err}
}

func asMySQLError(err error, errNo uint16) *mysql.MySQLError {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == errNo {
		return mysqlErr
	}
	return nil
}

// InsertFirmware adds an image to the storage (saves the images itself and it's metadata).
func (stor *Storage) InsertFirmware(ctx context.Context, imageMeta models.FirmwareImageMetadata, imageData []byte) (err error) {
	// Here we insert metadata to MySQL and data to BlobStorageClient.
	//
	// However it's a problem to process errors correctly if there will
	// be multiple workers.
	//
	// We don't want to send the same image multiple times to BlobStorageClient
	// (especially simultaneously), so we need to lock sending an image
	// with specific ID. The easiest way to do that is through MySQL. Thereby
	// we do the MySQL INSERT first.

	tx, err := stor.startTransaction(ctx)
	if err != nil {
		return ErrUnableToInsert{insertedValue: imageMeta.ImageID.String(), Err: fmt.Errorf("unable to start a transaction: %w", err)}
	}

	// To guarantee that each transaction will be closed we put Rollback/Commit
	// to a defer.
	defer func() {
		if err != nil {
			rollbackErr := tx.Rollback()
			if rollbackErr != nil {
				// To do not leave a transaction which could hang other workers we panic,
				// it with disconnect from MySQL and force-release the transaction.
				panic(fmt.Errorf("unable to rollback the transaction and do not how to remediate: %w", rollbackErr))
			}
			return
		}

		if commitErr := tx.Commit(); commitErr != nil {
			// override the retuning error:
			err = mySQLInsertError(imageMeta.ImageID.String(), fmt.Errorf("unable to commit the transaction: %w", commitErr))

			// just in case:
			_ = tx.Rollback()
		}
	}()

	values, columns, err := helpers.GetValuesAndColumns(&imageMeta, func(fieldName string, value interface{}) bool {
		if fieldName == "FirmwareVersion" || fieldName == "FirmwareDateString" || fieldName == "Filename" {
			strValue := value.(sql.NullString)
			return !strValue.Valid
		}
		return false
	})
	if err != nil {
		return fmt.Errorf("failed to parse reproducedPCRs: '%w'", err)
	}

	// Inserting the metadata and lock the `image_id`.
	columnsStr := constructColumns("", columns)
	placeholders := constructPlaceholders(len(columns))

	for tryCount := uint(1); ; tryCount++ {
		_, err = tx.Exec("INSERT INTO `firmware_image_metadata` ("+columnsStr+") VALUES ("+placeholders+")", values...)
		if err == nil {
			break
		}

		if asMySQLError(err, 1205) == nil {
			// Is not an MySQL error "1205" (see below), so it just an error we cannot remediate:
			return mySQLInsertError(imageMeta.ImageID.String(), fmt.Errorf("unable to insert the row: %w", err))
		}
		// See: https://dev.mysql.com/doc/refman/8.0/en/innodb-locks-set.html
		// > The first operation by session 1 acquires an exclusive lock for
		// > the row. The operations by sessions 2 and 3 both result in a
		// > duplicate-key error and they both request a shared lock for
		// > the row. When session 1 commits, it releases its exclusive lock
		// > on the row and the queued shared lock requests for sessions
		// > 2 and 3 are granted. At this point, sessions 2 and 3 deadlock:
		// > Neither can acquire an exclusive lock for the row because of
		// > the shared lock held by the other.
		//
		// In Facebook's MySQL deadlock detector is disabled, and we receive
		// error 1205:
		// "ERROR 1205 (HY000): Lock wait timeout exceeded; try restarting transaction: Timeout on record in index"
		// so we just retry the transaction (as the error message says).

		if tryCount >= stor.insertTriesLimit {
			stor.Logger.Errorf("reached the limit of tries to insert the metadata (%#+v), error: %v", imageMeta, err)
			return ErrUnableToInsert{insertedValue: imageMeta.ImageID.String(), Err: err}
		}
		stor.Logger.Warnf("insert timeout (%v), retrying the transaction...", err)
		err = tx.Rollback()
		if err != nil {
			// To do not leave a transaction which could hang other workers we panic,
			// it with disconnect from MySQL and force-release the transaction.
			panic(fmt.Errorf("unable to rollback the transaction (to re-start it) and do not how to remediate: %w", err))
		}
		tx, err = stor.startTransaction(ctx)
		if err != nil {
			return ErrUnableToInsert{insertedValue: imageMeta.ImageID.String(), Err: fmt.Errorf("unable to re-start a transaction: %w", err)}
		}
	}

	// Uploading the image to BlobStorageClient.
	err = stor.retryLoop(func() error {
		return stor.BlobStorage.Replace(ctx, imageMeta.BlobStorageKey(), imageData)
	})
	if err != nil {
		return ErrUnableToUpload{Key: imageMeta.BlobStorageKey(), Err: err}
	}

	// Set the "ts_upload".
	_, err = tx.Exec("UPDATE `firmware_image_metadata` SET `ts_upload` = ? WHERE `image_id` = ?",
		time.Now(), imageMeta.ImageID)
	if err != nil {
		return ErrUnableToInsert{insertedValue: imageMeta.ImageID.String(), Err: fmt.Errorf("unable to update the 'ts_upload' field: %w", err)}
	}
	return nil
}

func constructPlaceholders(cnt int) string {
	if cnt == 0 {
		return ""
	}
	return strings.Repeat("?, ", cnt-1) + "?"
}

func constructColumns(tableName string, columns []string) string {
	fullNames := make([]string, 0, len(columns))
	for _, column := range columns {
		if strings.Contains(column, "`") {
			panic(fmt.Sprintf("column <%s> contains a grave symbol", column))
		}
		var fullName string
		if tableName == "" {
			fullName = fmt.Sprintf("`%s`", column)
		} else {
			fullName = fmt.Sprintf("`%s`.`%s`", tableName, column)
		}
		fullNames = append(fullNames, fullName)
	}
	return strings.Join(fullNames, ",")
}

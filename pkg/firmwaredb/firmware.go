package rtpdb

import (
	"context"
	"errors"
	"fmt"
	"privatecore/firmware/analyzer/pkg/rtpdb/models"
	"time"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/jmoiron/sqlx"
)

// GetModelFamilyByModel returns a model family given model ID.
func GetModelFamilyByModel(ctx context.Context, db Querier, modelID uint64) (*ModelFamily, error) {
	// TODO: Cache this the outcome of this SELECT. Currently it is below 100 rows:
	//
	//           (scriptro:sys.xdb@xdb.rtp_firmware)> select count(*) from model_family;
	//			 +----------+
	//			 | count(*) |
	//			 +----------+
	//			 |       82 |
	//			 +----------+
	//			 1 row in set (0.13 sec)
	var modelFamilyCandidates ModelFamilies
	query := fmt.Sprintf("SELECT * FROM `model_family` WHERE `model_ids` LIKE '%%%d%%'", modelID)
	err := sqlx.SelectContext(ctx, db, &modelFamilyCandidates, query)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrCancelled{Err: err}
		}
		return nil, fmt.Errorf("unable to query model families with query '%s': %w", query, err)
	}

	modelFamily, err := modelFamilyCandidates.FindByModelID(modelID)
	if err != nil {
		return nil, fmt.Errorf("unable to find model family: %w", err)
	}

	return modelFamily, nil
}

// GetFirmwareByModel returns the firmware image metadata of the image for the model
// with id "modelID".
func GetFirmwareByModel(ctx context.Context, db Querier, modelID uint64) (*Firmware, error) {
	modelFamily, err := GetModelFamilyByModel(ctx, db, modelID)
	if err != nil {
		return nil, fmt.Errorf("unable to get model family by model ID %d: %w", modelID, err)
	}

	var result []Firmware
	query := "SELECT * FROM `firmware` WHERE `model_family_id` = ?"
	err = sqlx.Select(db, &result, query, modelFamily.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to query firmware metadata with query '%s': %w", query, err)
	}
	if len(result) != 1 {
		return nil, fmt.Errorf("expected one row, but received %d rows", len(result))
	}

	return &result[0], nil
}

// GetFirmwaresByVersionAndDate returns all firmware images metadata for the image with
// version "firmwareVersion" and date string "firmwareDateString".
//
// Firmware version and date is usually the variables used to check
// PCR0 allowlists.
func GetFirmwaresByVersionAndDate(ctx context.Context, db Querier, firmwareVersion, firmwareDateString string) ([]Firmware, error) {
	// There are two ways to set the firmware release date in the RTP firmware table:
	// by a string in field "fw_date" or by unixtime in field "firmware_date".
	// We assume that the date should be interpreted in UTC, but we not sure.
	//
	// Actually the whole approach with direct access to the MySQL table
	// should be deprecated very soon -- it is said as this moment [2020 year]
	// Yannick Brosseau does some work to provide a new interface to the
	// RTP firmware table data. So I propose to fix this on-need-basis and just
	// remove the whole package when it will be possible.
	var result []Firmware
	firmwareDate, err := time.Parse("01/02/2006 MST", firmwareDateString+" UTC")
	if err != nil {
		return nil, fmt.Errorf("invalid date '%s': %w", firmwareDateString, err)
	}
	year, month, day := firmwareDate.UTC().Date()
	firmwareDateUnixStart := time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Unix()
	firmwareDateUnixEnd := time.Date(year, month, day, 23, 59, 59, 999999999, time.UTC).Unix()

	query := "SELECT * FROM `firmware` WHERE `fw_version` = ? AND (`fw_date` = ? OR `firmware_date` BETWEEN ? AND ?)"
	args := []interface{}{firmwareVersion, firmwareDateString, firmwareDateUnixStart, firmwareDateUnixEnd}
	err = sqlx.SelectContext(ctx, db, &result, query, args...)
	if err != nil {
		return nil, fmt.Errorf("unable to query firmware metadata: %w", err)
	}
	return result, nil
}

// GetFirmwareByID returns firmware image by its row id
func GetFirmwareByID(ctx context.Context, db Querier, rowID uint64) (Firmware, error) {
	var result []Firmware
	query := "SELECT * FROM `firmware` WHERE `id` = ?"
	err := sqlx.SelectContext(ctx, db, &result, query, rowID)
	if err != nil {
		return Firmware{}, fmt.Errorf("unable to query firmware metadata: %w", err)
	}
	if len(result) > 1 {
		// we should update no more than a single item, because rowID is a primary key
		panic(fmt.Sprintf("unexepectedly high number of affected rows: '%d', row id: %d", len(result), rowID))
	}
	if len(result) == 0 {
		return Firmware{}, fmt.Errorf("no firmwares are found")
	}
	return result[0], nil
}

// GetFirmwares returns firmware metadata according to the filters.
func GetFirmwares(ctx context.Context, db Querier, filters ...Filter) ([]Firmware, error) {
	whereCond, args := Filters(filters).WhereCond()
	logger := logger.FromCtx(ctx)
	logger.Debugf("whereCond:'%s', args:%v", whereCond, args)

	query := "SELECT * FROM `firmware` WHERE " + whereCond
	var preFiltered []Firmware
	err := sqlx.SelectContext(ctx, db, &preFiltered, query, args...)
	if err != nil {
		return nil, fmt.Errorf("unable to query firmware metadata using query '%s' with arguments %v: %w", query, args, err)
	}

	// If it was impossible to effectively filter something using SQL WHERE condition,
	// where do post filtering here:
	var filtered []Firmware
	for _, fw := range preFiltered {
		if !Filters(filters).Match(&fw) {
			logger.Debugf("entry %d:%s:%s was filtered out", fw.ID, fw.FWVersion, fw.GetDate())
			continue
		}
		logger.Debugf("entry %d:%s:%s matches, adding", fw.ID, fw.FWVersion, fw.GetDate())
		filtered = append(filtered, fw)
	}

	return filtered, nil
}

// GetFirmwaresByType returns all firmware images metadata for specified firmware types
func GetFirmwaresByType(ctx context.Context, db Querier, firmwareTypes ...FirmwareType) ([]Firmware, error) {
	query, args, err := sqlx.In("SELECT * FROM `firmware` WHERE `firmware_type` IN (?)", firmwareTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to create a query: %w", err)
	}
	var result []Firmware
	err = sqlx.SelectContext(ctx, db, &result, query, args...)
	if err != nil {
		return nil, fmt.Errorf("unable to query firmware metadata: %w", err)
	}
	return result, nil
}

// GetLatestFirmwareByVersion returns latest firmware based on given version
func GetLatestFirmwareByVersion(ctx context.Context, db Querier, firmwareVersion string) (Firmware, error) {
	var result []Firmware
	query := "SELECT * FROM `firmware` WHERE `fw_version` = ? AND `is_latest_firmware` = 1 ORDER BY `firmware_date` DESC"
	args := []interface{}{firmwareVersion}
	err := sqlx.SelectContext(ctx, db, &result, query, args...)
	if err != nil {
		return Firmware{}, fmt.Errorf("unable to query firmware metadata: %w", err)
	}
	if len(result) == 0 {
		return Firmware{}, fmt.Errorf("no firmwares are found")
	}
	if !result[0].IsLatestFirmware {
		return Firmware{}, fmt.Errorf("query did not return latest value for: %s", firmwareVersion)
	}

	return result[0], nil
}

// AtomicUpdateFirmwareHash tries to update fw_hash column of a specified row only if that column currently contains a certain value
func AtomicUpdateFirmwareHash(ctx context.Context, db RWAccess, rowID uint64, newValue, previousValue models.FWHashSerialized) (updated bool, err error) {
	res, err := db.ExecContext(ctx, "UPDATE `firmware` SET `fw_hash` = ? WHERE `id` = ? AND `fw_hash` = ?", newValue, rowID, previousValue)
	if err != nil {
		return false, fmt.Errorf("failed to execute query: %w", err)
	}

	cnt, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to determine the number of affected rows: %w", err)
	}

	if cnt > 1 {
		// we should update no more than a single item, because rowID is a primary key
		panic(
			fmt.Sprintf(
				"unexepectedly high number of affected rows: '%d', row id: %d, new/previos values: '%s'/'%s'",
				cnt,
				rowID,
				newValue, previousValue,
			),
		)
	}
	return cnt == 1, nil
}

// DeleteFirmwareEntryByID tries to delete an entry in the table based on provided row id
func DeleteFirmwareEntryByID(ctx context.Context, db RWAccess, rowID uint64) (bool, error) {
	res, err := db.ExecContext(ctx, "DELETE FROM firmware WHERE `id` = ?", rowID)
	if err != nil {
		return false, fmt.Errorf("failed to execute query: %w", err)
	}

	cnt, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to determine the number of affected rows: %w", err)
	}
	if cnt == 0 {
		return false, fmt.Errorf("no row was deleted")
	}
	if cnt > 1 {
		// we should delete no more than a single item, because rowID is a primary key
		panic(fmt.Sprintf("unexepectedly high number of affected rows: '%d', row id: %d", cnt, rowID))
	}
	return cnt == 1, nil
}

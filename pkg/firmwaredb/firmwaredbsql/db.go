package firmwaredbsql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/helpers"
)

type DB struct {
	DriverName string
	DSN        string
}

var _ firmwaredb.DB = (*DB)(nil)

func New(driverName, dsn string) (*DB, error) {
	db := &DB{
		DriverName: driverName,
		DSN:        dsn,
	}

	if err := db.ping(); err != nil {
		return nil, ErrPing{
			Err: err,
		}
	}

	return db, nil
}

func (db *DB) ping() error {
	conn, err := db.newConnection()
	if err != nil {
		return ErrConnect{
			Err: err,
		}
	}
	defer conn.Close()

	return conn.Ping()
}

func (db *DB) newConnection() (*sql.DB, error) {
	rawDB, err := sql.Open(db.DriverName, db.DSN)
	if err != nil {
		return nil, ErrOpen{Err: err}
	}
	return rawDB, nil
}

func (db *DB) Get(ctx context.Context, filters ...Filter) ([]*Firmware, error) {
	whereCond, args := Filters(filters).WhereCond()

	var columns []string
	for tableName, obj := range map[string]any{
		"firmware":                      &Firmware{},
		"firmware_measurement_type":     &FirmwareMeasurementType{},
		"firmware_measurement":          &FirmwareMeasurement{},
		"firmware_measurement_metadata": &FirmwareMeasurementMetadata{},
		"firmware_target":               &FirmwareTarget{},
	} {
		_, _columns, err := helpers.GetValuesAndColumns(obj, nil)
		if err != nil {
			return nil, ErrScan{Err: fmt.Errorf("unable to obtain pointers of values to scan to (table: '%s', object `%T`): %w", tableName, obj, err)}
		}
		for _, column := range _columns {
			columns = append(columns, fmt.Sprintf("`%s`.`%s`", tableName, column))
		}
	}

	query := "" +
		fmt.Sprintf("SELECT %s FROM `firmware` ", strings.Join(columns, ",")) +
		"RIGHT JOIN `firmware_target` ON `firmware_target`.`firmware_id` = `firmware`.`id` " +
		"LEFT JOIN `firmware_measurement` ON `firmware_measurement`.`firmware_id` = `firmware`.`id` " +
		"LEFT JOIN `firmware_measurement_type` ON `firmware_measurement_type`.`id` = `firmware_measurement`.`type_id` " +
		"LEFT JOIN `firmware_measurement_metadata` ON `firmware_measurement_metadata`.`type_id` = `firmware_measurement_type`.`id` " +
		"WHERE " + whereCond
	logger.FromCtx(ctx).Debugf("query:'%s', args:%v", query, args)

	conn, err := db.newConnection()
	if err != nil {
		return nil, ErrConnect{
			Err: err,
		}
	}
	defer conn.Close()

	rows, err := conn.Query(query, args...)
	if err != nil {
		return nil, ErrQuery{Err: err, Description: UnableToQuery{Query: query, Args: args}}
	}

	var preFiltered []*Firmware

	type id = int64
	firmwares := map[id]*Firmware{}
	firmwareMeasurementTypes := map[id]*FirmwareMeasurementType{}
	firmwareMeasurements := map[id]*FirmwareMeasurement{}
	firmwareMeasurementMetadatas := map[id]*FirmwareMeasurementMetadata{}
	firmwareTargets := map[id]*FirmwareTarget{}

	for {
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return nil, ErrScan{Err: err}
			}
			break
		}

		var (
			values []any

			firmware                    Firmware
			firmwareMeasurementType     FirmwareMeasurementType
			firmwareMeasurement         FirmwareMeasurement
			firmwareMeasurementMetadata FirmwareMeasurementMetadata
			firmwareTarget              FirmwareTarget
		)

		for tableName, obj := range map[string]any{
			"firmware":                      &firmware,
			"firmware_measurement_type":     &firmwareMeasurementType,
			"firmware_measurement":          &firmwareMeasurement,
			"firmware_measurement_metadata": &firmwareMeasurementMetadata,
			"firmware_target":               &firmwareTarget,
		} {
			_values, _, err := helpers.GetValuesAndColumns(obj, nil)
			if err != nil {
				return nil, ErrScan{Err: fmt.Errorf("unable to obtain pointers of values to scan to (table: '%s', object `%T`): %w", tableName, obj, err)}
			}
			values = append(values, _values...)
		}

		rows.Scan(values)

		firmwarePtr := firmwares[firmware.ID]
		if firmwarePtr == nil {
			firmwarePtr = &firmware
			firmwares[firmware.ID] = firmwarePtr
			preFiltered = append(preFiltered, firmwarePtr)
		}

		firmwareMeasurementTypePtr := firmwareMeasurementTypes[firmware.ID]
		if firmwareMeasurementTypePtr == nil {
			firmwareMeasurementTypePtr = &firmwareMeasurementType
			firmwareMeasurementTypes[firmwareMeasurementType.ID] = firmwareMeasurementTypePtr
		}

		firmwareMeasurementPtr := firmwareMeasurements[firmware.ID]
		if firmwareMeasurementPtr == nil {
			firmwareMeasurementPtr = &firmwareMeasurement
			firmwareMeasurements[firmwareMeasurement.ID] = firmwareMeasurementPtr
			firmwareMeasurement.FirmwareMeasurementType = firmwareMeasurementTypePtr
			firmwareMeasurement.Firmware = firmwarePtr
			firmwarePtr.Measurements = append(firmwarePtr.Measurements, firmwareMeasurementPtr)
		}

		firmwareTargetPtr := firmwareTargets[firmware.ID]
		if firmwareTargetPtr == nil {
			firmwareTargetPtr = &firmwareTarget
			firmwareTargets[firmwareTarget.ID] = firmwareTargetPtr
			firmwareTargetPtr.Firmware = firmwarePtr
			firmwarePtr.Targets = append(firmwarePtr.Targets, firmwareTargetPtr)
		}

		firmwareMeasurementMetadataPtr := firmwareMeasurementMetadatas[firmwareMeasurementMetadata.ID]
		if firmwareMeasurementMetadataPtr == nil {
			firmwareMeasurementMetadataPtr = &firmwareMeasurementMetadata
			firmwareMeasurementMetadatas[firmwareMeasurementMetadata.ID] = firmwareMeasurementMetadataPtr
			firmwareMeasurementTypePtr.Metadata = append(firmwareMeasurementTypePtr.Metadata, firmwareMeasurementMetadataPtr)
		}
	}

	// If it was impossible to effectively filter something using SQL WHERE condition,
	// where do post filtering here:
	var filtered []*Firmware
	for _, fw := range preFiltered {
		if !Filters(filters).Match(fw) {
			logger.FromCtx(ctx).Debugf("entry %d:%s was filtered out", fw.ID, fw.Version)
			continue
		}
		logger.FromCtx(ctx).Debugf("entry %d:%s matches, adding", fw.ID, fw.Version)
		filtered = append(filtered, fw)
	}

	return filtered, nil
}

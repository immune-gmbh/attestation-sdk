package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"

	"github.com/go-sql-driver/mysql"
)

// FindFirmwareFilter is a set of values to look for (concatenated through "AND"-s).
//
// If a field has a nil-value then it is not included to filter conditions.
type FindFirmwareFilter struct {
	// Here we include only indexed columns, see also models/image_metadata.sql

	// == exact values ==

	ImageID         *types.ImageID
	HashSHA2_512    types.HashValue
	HashBlake3_512  types.HashValue
	HashStable      types.HashValue
	Filename        *string
	FirmwareVersion *string

	// == non-exact values ==

	ImageIDPrefix []byte
}

// IsEmpty returns true if no filters are set
func (f FindFirmwareFilter) IsEmpty() bool {
	return reflect.ValueOf(f).IsZero()
}

// FindFirmwareOne locks (with a shared lock) the row and returns image metadata.
//
// Second returned variable is a function to release the lock on the row.
func (stor *Storage) FindFirmwareOne(ctx context.Context, filter FindFirmwareFilter) (*models.FirmwareImageMetadata, context.CancelFunc, error) {
	metas, unlockFn, err := stor.FindFirmware(ctx, filter)
	if err != nil {
		return nil, nil, err
	}

	switch len(metas) {
	case 0:
		unlockFn()
		return nil, nil, ErrNotFound{Query: "stor.Find()[0]"}
	case 1:
		return metas[0], unlockFn, nil
	default:
		unlockFn()
		return nil, nil, ErrTooManyEntries{Count: uint(len(metas))}
	}
}

// compileFirmwareImageWhereConds constructs a WHERE string for Query() using selected filters.
//
// For example:
//
//	FindFilters{TarballFilename: &[]string{"hello"}[0], FirmwareVersion: &[]string{"ver"}[0]}
//
// will result into:
//
//	("filename = ? AND firmware_version = ?", []interface{}{"hello", "ver"})
//
// And it could be used as:
//
//	db.Query("SELECT * FROM table WHERE "+whereConds, whereArgs...)
//
// See also unit-test: TestCompileWhereConds
func compileFirmwareImageWhereConds(filters FindFirmwareFilter) (string, []interface{}) {
	var whereConds []string
	var whereArgs []interface{}

	sample := models.FirmwareImageMetadata{}
	sampleStruct := reflect.ValueOf(&sample).Elem()
	filtersStruct := reflect.ValueOf(&filters).Elem()
	for i := 0; i < filtersStruct.NumField(); i++ {
		filterField := filtersStruct.Field(i)
		if filterField.IsZero() {
			continue
		}
		filterStructField := filtersStruct.Type().Field(i)
		var fieldName string
		switch {
		case strings.HasSuffix(filterStructField.Name, "Prefix"):
			fieldName = filterStructField.Name[:len(filterStructField.Name)-len("Prefix")]
		default:
			fieldName = filterStructField.Name
		}
		sampleStructField, ok := sampleStruct.Type().FieldByName(fieldName)
		if !ok {
			panic("should not happened")
		}
		sqlColumnName := strings.Split(sampleStructField.Tag.Get("db"), ",")[0]
		switch {
		case strings.HasSuffix(filterStructField.Name, "Prefix"):
			whereConds = append(whereConds, "`"+sqlColumnName+"` LIKE CONCAT(?, '%')")
		default:
			whereConds = append(whereConds, fmt.Sprintf("`%s` = ?", sqlColumnName))
		}
		whereArgs = append(whereArgs, reflect.Indirect(filterField).Interface())
	}
	return strings.Join(whereConds, " AND "), whereArgs
}

// FindFirmware locks (with a shared lock) the rows and returns image metadata.
//
// Second returned variable is a function to release the lock on the row.
func (stor *Storage) FindFirmware(ctx context.Context, filter FindFirmwareFilter) (imageMetas []*models.FirmwareImageMetadata, unlockFn context.CancelFunc, err error) {

	// Collecting WHERE conditions
	whereConds, whereArgs := compileFirmwareImageWhereConds(filter)
	if len(whereConds) == 0 {
		return nil, nil, ErrEmptyFilters{}
	}

	// We do a lock on the row, and to have an isolated way to
	// handle locks we create a transaction. We need an isolated way because
	// some other routine can use "stor.DB" at the same time.
	tx, err := stor.startTransaction(ctx)
	if err != nil {
		return nil, nil, ErrSelect{Err: err}
	}

	// In the SELECT below we lock the rows, and in this "defer" we handle the lock.
	defer func() {
		// If no error then return a lock-release function, if there **is**
		// an error then release the lock right away:
		unlockFunc := func() {
			errCommit := tx.Commit()
			if errCommit == nil {
				return
			}
			if errors.Is(errCommit, mysql.ErrInvalidConn) {
				// Lost connection, therefore the transaction will be reset
				// automatically.
				return
			}
			// To do not leave a transaction which could hang other workers we panic,
			// it with disconnect from MySQL and force-release the transaction.
			panic(fmt.Errorf("unable to commit the transaction and do not how to remediate: %w", errCommit))
		}
		if err != nil {
			unlockFunc()
			return
		}

		unlockFn = unlockFunc
	}()

	// SELECT and lock
	_, columns, err := helpers.GetValuesAndColumns(&models.FirmwareImageMetadata{}, nil)
	query := fmt.Sprintf("SELECT %s FROM `image_metadata` WHERE %s LOCK IN SHARE MODE",
		strings.Join(columns, ","),
		whereConds,
	)

	err = tx.Select(&imageMetas, query, whereArgs...)
	stor.Logger.Debugf("query: '%s' with args %v result: err:%v", query, whereArgs, err)
	if err != nil {
		return nil, nil, ErrSelect{Err: err}
	}
	if len(imageMetas) == 0 {
		return nil, nil, ErrNotFound{Query: fmt.Sprintf("%s %s", query, whereArgs)}
	}

	// Everything OK
	return
}

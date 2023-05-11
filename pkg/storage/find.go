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
	"github.com/jmoiron/sqlx"
)

// FindFilter is a set of values to look for (concatenated through "AND"-s).
//
// If a field has a nil-value then it is not included to filter conditions.
type FindFilter struct {
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
func (f FindFilter) IsEmpty() bool {
	return reflect.ValueOf(f).IsZero()
}

// FindOne locks (with a shared lock) the row and returns image metadata.
//
// Second returned variable is a function to release the lock on the row.
func (stor *Storage) FindOne(ctx context.Context, filter FindFilter) (*models.ImageMetadata, context.CancelFunc, error) {
	metas, unlockFn, err := stor.Find(ctx, filter)
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

// FindOneReproducedPCRs returns reproduced single PCRs item by unique search key
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//       management of metadata in MySQL and data in Manifold for firmware images. All the rest
//       entities should not be accessed through Storage. Otherwise locking, transactions and other
//       usual stuff is pretty cludgy.
func (stor *Storage) FindOneReproducedPCRs(ctx context.Context, key models.UniqueKey) (models.ReproducedPCRs, error) {
	_, columns, err := helpers.GetValuesAndColumns(&models.ReproducedPCRs{}, nil)
	if err != nil {
		return models.ReproducedPCRs{}, err
	}

	var result []models.ReproducedPCRs
	query := fmt.Sprintf(
		"SELECT %s FROM `reproduced_pcrs` WHERE `hash_stable` = ? AND `registers_sha512` = ? AND `tpm_device` = ?",
		strings.Join(columns, ","),
	)
	if err := sqlx.Select(stor.DB, &result, query, key.HashStable, key.RegistersSHA512, key.TPMDevice); err != nil {
		return models.ReproducedPCRs{}, fmt.Errorf("unable to query firmware metadata: %w", err)
	}
	if len(result) == 0 {
		return models.ReproducedPCRs{}, ErrNotFound{Query: query}
	}
	if len(result) > 1 {
		panic(fmt.Errorf("unexepectedly high number of affected rows: '%d'", len(result)))
	}
	return result[0], nil
}

// SelectReproducedPCRs selects all reproduced PCR values
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//       management of metadata in MySQL and data in Manifold for firmware images. All the rest
//       entities should not be accessed through Storage. Otherwise locking, transactions and other
//       usual stuff is pretty cludgy.
func (stor *Storage) SelectReproducedPCRs(ctx context.Context) ([]models.ReproducedPCRs, error) {
	_, columns, err := helpers.GetValuesAndColumns(&models.ReproducedPCRs{}, nil)
	if err != nil {
		return nil, err
	}

	var result []models.ReproducedPCRs
	query := fmt.Sprintf(
		"SELECT %s FROM `reproduced_pcrs`",
		strings.Join(columns, ","),
	)
	if err := sqlx.Select(stor.DB, &result, query); err != nil {
		return nil, fmt.Errorf("unable to query firmware metadata: %w", err)
	}
	return result, nil
}

func ptr[T any](v T) *T {
	return &v
}

// SelectReproducedPCRsWithImageMetadata selects an INNER JOIN of reproduced PCRs with image metadatas.
// The indexes of both returned slices corresponds to each other.
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//       management of metadata in MySQL and data in Manifold for firmware images. All the rest
//       entities should not be accessed through Storage. Otherwise locking, transactions and other
//       usual stuff is pretty cludgy.
func (stor *Storage) SelectReproducedPCRsWithImageMetadata(ctx context.Context) ([]models.ReproducedPCRs, []models.ImageMetadata, error) {
	var (
		leftRow  models.ReproducedPCRs
		rightRow models.ImageMetadata
	)
	leftValues, leftColumns, err := helpers.GetValuesAndColumns(&leftRow, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get column for the table of reproduced PCRs")
	}
	rightValues, rightColumns, err := helpers.GetValuesAndColumns(&rightRow, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get column for the table of image metadata")
	}

	query := fmt.Sprintf(
		"SELECT %s,%s FROM `reproduced_pcrs` `pcrs` JOIN `image_metadata` `meta` ON `pcrs`.`hash_stable` = `meta`.`hash_stable`",
		constructColumns("pcrs", leftColumns),
		constructColumns("meta", rightColumns),
	)
	rows, err := stor.DB.Query(query)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to query '%s': %w", query, err)
	}
	defer rows.Close()

	var (
		leftResult  []models.ReproducedPCRs
		rightResult []models.ImageMetadata
	)

	allValues := append(append([]any{}, leftValues...), rightValues...)
	for rows.Next() {
		rightRow.ImageID = types.ImageID{}
		err := rows.Scan(allValues...)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to scan values: %w (query: '%s')", err, query)
		}
		leftResult = append(leftResult, leftRow)
		rightResult = append(rightResult, rightRow)
	}

	return leftResult, rightResult, nil
}

// compileImageWhereConds constructs a WHERE string for Query() using selected filters.
//
// For example:
//   FindFilters{TarballFilename: &[]string{"hello"}[0], FirmwareVersion: &[]string{"ver"}[0]}
// will result into:
//   ("filename = ? AND firmware_version = ?", []interface{}{"hello", "ver"})
// And it could be used as:
//   db.Query("SELECT * FROM table WHERE "+whereConds, whereArgs...)
//
// See also unit-test: TestCompileWhereConds
func compileImageWhereConds(filters FindFilter) (string, []interface{}) {
	var whereConds []string
	var whereArgs []interface{}

	sample := models.ImageMetadata{}
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

// Find locks (with a shared lock) the rows and returns image metadata.
//
// Second returned variable is a function to release the lock on the row.
func (stor *Storage) Find(ctx context.Context, filter FindFilter) (imageMetas []*models.ImageMetadata, unlockFn context.CancelFunc, err error) {

	// Collecting WHERE conditions
	whereConds, whereArgs := compileImageWhereConds(filter)
	if len(whereConds) == 0 {
		return nil, nil, ErrEmptyFilters{}
	}

	// We do a lock on the row, and to have an isolated way to
	// handle locks we create a transaction. We need an isolated way because
	// some other routine can use "stor.DB" at the same time.
	tx, err := stor.DB.Beginx()
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
	_, columns, err := helpers.GetValuesAndColumns(&models.ImageMetadata{}, nil)
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

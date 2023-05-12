package firmwarestorage

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/jmoiron/sqlx"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarestorage/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarestorage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

// InsertAnalyzeReport adds information about performed analysis.
//
// `report` should be not-nil, but `ID` field should be zero.
//
// On success also:
// * `ID` is set.
// * `report.Reports` are also saved and: `ID` and `AnalyzerReportID` are also set.
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//
//	management of metadata in MySQL and data in Manifold for firmware images. All the rest
//	entities should not be accessed through Storage. Otherwise locking, transactions and other
//	usual stuff is pretty cludgy.
func (fwStor *FirmwareStorage) InsertAnalyzeReport(ctx context.Context, report *models.AnalyzeReport) (retErr error) {
	log := logger.FromCtx(ctx)
	log.Debugf("saving the Analyzer report...")
	defer func() {
		log.Debugf("saving the Analyzer report outcome: -> %v", retErr)
	}()
	if report == nil {
		return fmt.Errorf("result is nil")
	}
	if report.ID != 0 {
		return fmt.Errorf("ID is already non-zero: %d", report.ID)
	}

	values, columns, err := helpers.GetValuesAndColumns(report, func(fieldName string, value interface{}) bool {
		return fieldName == "ID"
	})
	if err != nil {
		return fmt.Errorf("unable to get query parameters: %w", err)
	}

	tx, err := fwStor.startTransaction(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}

	defer func() {
		if retErr == nil && report.ID == 0 {
			err = fmt.Errorf("report ID is zero, something went wrong")
		}
		if retErr == nil {
			newErr := tx.Commit()
			if newErr != nil {
				retErr = fmt.Errorf("unable to commit the transaction: %w", newErr)
			}
			return
		}

		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			panic(fmt.Errorf("unable to rollback the transaction and do not know to react on that: %w", rollbackErr))
		}
	}()

	query := fmt.Sprintf("INSERT INTO `analyze_report` (%s) VALUES (%s)", constructColumns("", columns), constructPlaceholders(len(columns)))
	sqlResult, err := tx.Exec(query, values...)
	if err != nil {
		return fmt.Errorf("unable to perform query '%s' with arguments %#+v: %w", query, values, err)
	}
	lastID, err := sqlResult.LastInsertId()
	if err != nil {
		return fmt.Errorf("unable to get last inserted ID: %w", err)
	}

	report.ID = uint64(lastID)

	for idx := range report.AnalyzerReports {
		analyzerReport := &report.AnalyzerReports[idx]
		analyzerReport.AnalyzeReportID = report.ID
		err := fwStor.insertAnalyzerReport(tx.Tx, analyzerReport)
		if err != nil {
			return fmt.Errorf("unable to insert analyzer report #%d: %w", idx, err)
		}
	}

	return nil
}

func (fwStor *FirmwareStorage) insertAnalyzerReport(tx *sql.Tx, report *models.AnalyzerReport) error {
	values, columns, err := helpers.GetValuesAndColumns(report, func(fieldName string, value interface{}) bool {
		return fieldName == "ID"
	})
	if err != nil {
		return fmt.Errorf("unable to get query parameters: %w", err)
	}

	query := fmt.Sprintf("INSERT INTO `analyzer_report` (%s) VALUES (%s)", constructColumns("", columns), constructPlaceholders(len(columns)))
	sqlResult, err := tx.Exec(query, values...)
	if err != nil {
		return fmt.Errorf("unable to perform query '%s' with arguments %#+v: %w", query, values, err)
	}
	lastID, err := sqlResult.LastInsertId()
	if err != nil {
		return fmt.Errorf("unable to get last inserted ID: %w", err)
	}

	report.ID = uint64(lastID)
	err = fwStor.aoscWorkaroundBuildAnalyzerReportIndexes(tx, report)
	if err != nil {
		return fmt.Errorf("unable to build indexes: %w", err)
	}
	return nil
}

// AnalyzeReportFindFilter is a set of values to look for (concatenated through "AND"-s).
//
// If a field has a nil-value then it is not included to filter conditions.
type AnalyzeReportFindFilter struct {
	ID          *uint64
	JobID       *types.JobID
	AssetID     *int32
	ProcessedAt *sql.NullTime

	// Firmware image referenced in the report.
	ActualFirmware FindFilter
}

type analyzeReportFindFilter struct {
	ID          *uint64
	JobID       *types.JobID
	AssetID     *int32
	ProcessedAt *sql.NullTime

	ActualFirmwareImageIDs []types.ImageID
}

// FindAnalyzeReports finds and locks existing AnalyzeReports including the related AnalyzerReports.
//
// The rows are write-locks as part of `tx` transaction. To unlock the rows either Commit or Rollback
// the transaction.
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//
//	management of metadata in MySQL and data in Manifold for firmware images. All the rest
//	entities should not be accessed through Storage. Otherwise locking, transactions and other
//	usual stuff is pretty cludgy (e.g. see the `tx` which semantically partially duplicates `stor.DB`).
func (fwStor *FirmwareStorage) FindAnalyzeReports(
	ctx context.Context,
	filterInput AnalyzeReportFindFilter,
	tx *sqlx.Tx,
	limit uint, // 0 -- no limit
) (
	[]*models.AnalyzeReport,
	error,
) {
	filter := &analyzeReportFindFilter{
		ID:          filterInput.ID,
		JobID:       filterInput.JobID,
		AssetID:     filterInput.AssetID,
		ProcessedAt: filterInput.ProcessedAt,
	}

	if filterInput.ActualFirmware.ImageID != nil {
		// If filterInput.ActualFirmware contains only ImageID then we can pass it as is,
		// otherwise fallback to requesting ImageIDs.
		imageID := *filterInput.ActualFirmware.ImageID
		filterInput.ActualFirmware.ImageID = nil
		if filterInput.ActualFirmware.IsEmpty() {
			filter.ActualFirmwareImageIDs = append(filter.ActualFirmwareImageIDs, imageID)
		} else {
			filterInput.ActualFirmware.ImageID = &imageID
		}
	}

	if !filterInput.ActualFirmware.IsEmpty() {
		imageMetas, unlockFn, err := fwStor.Find(ctx, filterInput.ActualFirmware)
		if err != nil {
			return nil, fmt.Errorf("unable to find image references given filter %#+v: %w", filterInput.ActualFirmware, err)
		}
		unlockFn()

		for _, imageMeta := range imageMetas {
			filter.ActualFirmwareImageIDs = append(filter.ActualFirmwareImageIDs, imageMeta.ImageID)
		}
	}

	result, err := fwStor.findAnalyzeReports(ctx, tx, filter, limit)
	if err != nil {
		return nil, fmt.Errorf("unable to get the analyze report by filter %#+v: %w", filter, err)
	}

	for _, report := range result {
		// TODO: fetch all analyzer reports at once, instead of by one for each AnalyzeReport
		report.AnalyzerReports, err = fwStor.findAnalyzerReportsByAnalyzeReportID(ctx, tx, report.ID)
		if err != nil {
			return nil, fmt.Errorf("unable to get the reports of analyzers by analyze ID %d: %w", report.ID, err)
		}
	}

	return result, nil
}

func (fwStor *FirmwareStorage) findAnalyzeReports(
	ctx context.Context,
	tx *sqlx.Tx,
	filter *analyzeReportFindFilter,
	limit uint, // 0 -- no limit
) ([]*models.AnalyzeReport, error) {
	var whereConds []string
	var whereArgs []any
	var joinStatements []string

	if filter.ActualFirmwareImageIDs != nil {
		// ActualFirmware is an input an input to an analyzer, so to find the requested AnalyzeReport-s
		// we need to JOIN them with AnalyzerReport-s and filter there by input_actual_firmware_image_id.
		//
		// AnalyzerReport's table `analyzer_report` has field `analyze_report_id` which contains the
		// ID of an AnalyzeReport (table `analyze_report`).
		//
		// An example outcome:
		// (scriptro:sys.xdb@xdb.afas)> select * from analyze_report join analyzer_report on analyzer_report.analyze_report_id = analyze_report.id where analyzer_id='DiffMeasuredBoot' and diagnosis_code IS NOT NULL limit 1\G
		// *************************** 1. row ***************************
		//                               id: 4193
		//                           job_id: 0xCB63856017E448C5B90C2AEBFE8309F5
		//                         asset_id: 289649253
		//                        timestamp: 2022-11-10 17:31:49
		//                     processed_at: 2022-11-11 11:01:21
		//                        group_key: NULL
		//                               id: 11013
		//                analyze_report_id: 4193
		//                      analyzer_id: DiffMeasuredBoot
		//                       exec_error: NULL
		//                            input: {"AssetID": 289649253, "ActualPCR0": "4lh54GB6ZmMElEnWrS3Ngf+3vmQ=", "ActualRegisters": {}, "ActualFirmwareBlob": {"Blob": {"github.com/immune-gmbh/AttestationFailureAnalysisService/server/controller/types.AnalyzerFirmwareAccessor": {"ImageID": "29ab3067dd805e21dc1f686bb5d4050fed61db9466edab018a7a6a4e4ea23cb90bbf99320b772d6b1ad4c56257052c72579cb82d3f35e01ed2de87cd9701df75a4e18db3d5b8a48d4c40352efda0279cc5aa586004daa5398c0ce133a879d5460186cf2ade9caad54e652d2c7303c922165277a895f4dd860d22a66db3455cce"}}}, "OriginalFirmwareBlob": {"Blob": {"github.com/immune-gmbh/AttestationFailureAnalysisService/server/controller/types.AnalyzerFirmwareAccessor": [...]}
		//                   diagnosis_code: FirmwareVersionMismatch
		//   input_actual_firmware_image_id: 0x29AB3067DD805E21DC1F686BB5D4050FED61DB9466EDAB018A7A6A4E4EA23CB90BBF99320B772D6B1AD4C56257052C72579CB82D3F35E01ED2DE87CD9701DF75A4E18DB3D5B8A48D4C40352EFDA0279CC5AA586004DAA5398C0CE133A879D5460186CF2ADE9CAAD54E652D2C7303C922165277A895F4DD860D22A66DB3455CCE
		// input_original_firmware_image_id: 0x49E2C8F354E589DD361911204A365289AE5319795E38290F1BFCBA6977904A9587AA4FCD9266D6AF3F01EDD6467CAD5FEB3F23769BB770DD98A3F3DB6A892F13C7949E72308F081B187ED77DB2A32F8210636998C201F50EBC3F0CAFFB56CF71303CBD643203FC1A54932347D48FC2F2065F15777203CA02C13CB4C207A74988
		//                  exec_error_code: OK
		// 1 row in set (0.14 sec)
		//
		// Here fields `id` through `group_key` belong to `analyze_report`, and `id` through `exec_error_code` belong to `analyzer_report`.

		var imageIDs []string
		for _, imageID := range filter.ActualFirmwareImageIDs {
			imageIDs = append(imageIDs, fmt.Sprintf("0x%X", imageID[:]))
		}
		joinStatements = append(joinStatements, "JOIN `analyzer_report` ON `analyze_report`.`id` = `analyzer_report`.`analyze_report_id`")
		whereConds = append(whereConds, fmt.Sprintf("`input_actual_firmware_image_id` IN (%s)", strings.Join(imageIDs, ", ")))
	}

	if filter.ID != nil {
		whereConds = append(whereConds, "`analyze_report`.`id` = ?")
		whereArgs = append(whereArgs, *filter.ID)
	}
	if filter.JobID != nil {
		whereConds = append(whereConds, "`analyze_report`.`job_id` = ?")
		whereArgs = append(whereArgs, *filter.JobID)
	}
	if filter.AssetID != nil {
		whereConds = append(whereConds, "`analyze_report`.`asset_id` = ?")
		whereArgs = append(whereArgs, *filter.AssetID)
	}
	if filter.ProcessedAt != nil {
		whereConds = append(whereConds, "`analyze_report`.`processed_at` = ?")
		if filter.ProcessedAt.Valid {
			whereArgs = append(whereArgs, *filter.ProcessedAt)
		} else {
			whereArgs = append(whereArgs, "0000-00-00 00:00:00")
		}
	}
	_, columns, err := helpers.GetValuesAndColumns(&models.AnalyzeReport{}, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to gather column names: %w", err)
	}
	var whereTotal string
	if len(whereConds) > 0 {
		whereTotal = "WHERE (" + strings.Join(whereConds, ") AND (") + ")"
	}
	query := fmt.Sprintf(
		"SELECT %s FROM `analyze_report` %s %s ORDER BY `analyze_report`.`id` DESC",
		constructColumns("analyze_report", columns),
		strings.Join(joinStatements, " "),
		whereTotal,
	)
	if limit != 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if tx != nil {
		query += " FOR UPDATE"
	}

	logger.FromCtx(ctx).Debugf("query: <%s>; args: %v", query, whereArgs)
	var _reports []models.AnalyzeReport
	if err := sqlx.Select(fwStor.querier(tx), &_reports, query, whereArgs...); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("unable to query analyze reports by analyze reports using query '%s' with args '%s': %w", query, whereArgs, err)
	}

	var reports []*models.AnalyzeReport
	for idx := range _reports {
		reports = append(reports, &_reports[idx])
	}

	return reports, nil
}

func (fwStor *FirmwareStorage) querier(tx *sqlx.Tx) sqlx.Queryer {
	if tx != nil {
		return tx
	}
	return fwStor.DB
}

func (fwStor *FirmwareStorage) findAnalyzerReportsByAnalyzeReportID(
	ctx context.Context,
	tx *sqlx.Tx,
	analyzeReportID uint64,
) ([]models.AnalyzerReport, error) {
	var reports []models.AnalyzerReport

	_, columns, err := helpers.GetValuesAndColumns(&models.AnalyzerReport{}, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to gather column names: %w", err)
	}

	query := fmt.Sprintf(
		"SELECT %s FROM `analyzer_report` WHERE `analyze_report_id` = ?",
		constructColumns(`analyzer_report`, columns),
	)
	if tx != nil {
		query += " FOR UPDATE"
	}
	logger.FromCtx(ctx).Debugf("query: %s; analyzeReportID==%d", query, analyzeReportID)
	if err := sqlx.Select(fwStor.querier(tx), &reports, query, analyzeReportID); err != nil {
		return nil, fmt.Errorf("unable to query analyzer reports by analyze report ID %d: %w", analyzeReportID, err)
	}

	return reports, nil
}

// FindAnalyzerReport finds and locks an AnalyzerReport, given its ID.
//
// The rows are write-locks as part of `tx` transaction. To unlock the rows either Commit or Rollback
// the transaction.
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//
//	management of metadata in MySQL and data in Manifold for firmware images. All the rest
//	entities should not be accessed through Storage. Otherwise locking, transactions and other
//	usual stuff is pretty cludgy (e.g. see the `tx` which semantically partially duplicates `stor.DB`).
func (fwStor *FirmwareStorage) FindAnalyzerReport(
	tx *sqlx.Tx,
	analyzerReportID int64,
) (*models.AnalyzerReport, error) {
	_, columns, err := helpers.GetValuesAndColumns(&models.AnalyzerReport{}, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to gather column names: %w", err)
	}

	query := fmt.Sprintf(
		"SELECT %s FROM `analyzer_report` WHERE `id` = ?",
		constructColumns(`analyzer_report`, columns),
	)

	var report models.AnalyzerReport
	if err := sqlx.Get(fwStor.querier(tx), &report, query, analyzerReportID); err != nil {
		return nil, fmt.Errorf("unable to query analyzer reports by analyzer report ID %d: %w", analyzerReportID, err)
	}

	return &report, nil
}

func uint64SliceToSQLList(in []uint64) string {
	if len(in) == 0 {
		return "()"
	}

	var s []string
	for _, v := range in {
		s = append(s, strconv.FormatUint(v, 10))
	}
	return fmt.Sprintf("(%s)", strings.Join(s, ","))
}

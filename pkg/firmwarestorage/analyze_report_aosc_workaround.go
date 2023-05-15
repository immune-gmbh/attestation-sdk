package firmwarestorage

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/generated/diffanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarestorage/models"

	controllertypes "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/types"
)

// AOSC does not support neither VIRTUAL columns nor `DEFAULT (..stuff-here..)` column properties,
// thus the indexed value is not calculatable on the DB side. Therefore we have to add this hack
// to calculate the indexed values on the AFAS side and push them explicitely to the DB.
//
// This all function is an abstraction leak. But until AOSC is fixed I see no other simple way.
// Package `storage` should not depend on `controllertypes` and should not know anything about
// internals of analysis.Input.
func (fwStor *FirmwareStorage) aoscWorkaroundBuildAnalyzerReportIndexes(tx *sql.Tx, report *models.AnalyzerReport) error {
	if report.ID == 0 {
		return fmt.Errorf("report.ID == 0")
	}

	sdfsdf

	var (
		columns []string
		values  []any
	)

	var diagnosisCode string
	if report.Report != nil {
		switch custom := report.Report.Custom.(type) {
		// We currently are interested in building an index using one specific diagnosis,
		// everything else is ignored.
		case diffanalysis.CustomReport:
			diagnosisCode = custom.Diagnosis.String()
		}
	}

	if diagnosisCode != "" {
		columns = append(columns, "diagnosis_code")
		values = append(values, diagnosisCode)
	}

	actualFirmwareBlobTypeID, err := analysis.TypeRegistry().TypeIDOf(analysis.ActualFirmwareBlob{})
	if err != nil {
		return fmt.Errorf("internal error: unable to get the TypeID of ActualFirmwareBlob: %w", err)
	}

	originalFirmwareBlobTypeID, err := analysis.TypeRegistry().TypeIDOf(analysis.OriginalFirmwareBlob{})
	if err != nil {
		return fmt.Errorf("internal error: unable to get the TypeID of OriginalFirmwareBlob: %w", err)
	}

	if fw, ok := report.Input[actualFirmwareBlobTypeID].(analysis.ActualFirmwareBlob); ok {
		if actualFirmwareAccessor, ok := fw.Blob.(*controllertypes.AnalyzerFirmwareAccessor); ok {
			columns = append(columns, "input_actual_firmware_image_id")
			values = append(values, &actualFirmwareAccessor.ImageID)
		}
	}
	if fw, ok := report.Input[originalFirmwareBlobTypeID].(analysis.OriginalFirmwareBlob); ok {
		if originalFirmwareAccessor, ok := fw.Blob.(*controllertypes.AnalyzerFirmwareAccessor); ok {
			columns = append(columns, "input_original_firmware_image_id")
			values = append(values, &originalFirmwareAccessor.ImageID)
		}
	}
	var execErrorCode string
	switch {
	case report.ExecError.Err == nil:
		execErrorCode = "OK"
	case errors.As(report.ExecError.Err, &analysis.ErrNotApplicable{}):
		execErrorCode = "ErrNotApplicable"
	default:
		execErrorCode = "ErrOther"
	}
	columns = append(columns, "exec_error_code")
	values = append(values, execErrorCode)

	if len(columns) == 0 {
		// nothing to change
		return nil
	}
	query := "UPDATE `analyzer_report` SET `" + strings.Join(columns, "`=?,`") + "`=? WHERE id=?"
	values = append(values, report.ID)

	sqlResult, err := tx.Exec(query, values...)
	if err != nil {
		return fmt.Errorf("unable to perform query '%s' with arguments %#+v: %w", query, values, err)
	}
	affected, err := sqlResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("unable to get the RowsAffected value: %w", err)
	}

	if affected != 1 {
		return fmt.Errorf("expected to affect one row, but affected %d row(s)", affected)
	}

	return nil
}

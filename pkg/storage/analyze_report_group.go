package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
)

// GetAnalyzeReportGroup finds and locks an existing AnalyzeReportGroup.
//
// The rows are write-locks as part of `tx` transaction. To unlock the rows either Commit or Rollback
// the transaction.
//
// if `fetchAnalyzeReports` is true then also fetches related AnalyzeReports into field AnalyzeReports.
//
// Returns (nil, nil) if such group is was not found.
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//
//	management of metadata in MySQL and data in BlobStorage for firmware images. All the rest
//	entities should not be accessed through Storage. Otherwise locking, transactions and other
//	usual stuff is pretty cludgy (e.g. see the `tx` which semantically partially duplicates `stor.DB`).
func (stor *Storage) GetAnalyzeReportGroup(
	ctx context.Context,
	key models.AnalyzeReportGroupKey,
	tx *sqlx.Tx,
	fetchAnalyzeReports bool,
) (
	*models.AnalyzeReportGroup,
	error,
) {
	if tx == nil {
		return nil, fmt.Errorf("case 'tx == nil' is not supported, yet")
	}
	if fetchAnalyzeReports {
		return nil, fmt.Errorf("fetching of related analyze reports is not supported, yet")
	}

	var group models.AnalyzeReportGroup
	_, columns, err := helpers.GetValuesAndColumns(&group, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to gather column names: %w", err)
	}

	query := fmt.Sprintf(
		"SELECT %s FROM `analyze_report_group` WHERE `group_key` = ? FOR UPDATE",
		constructColumns(`analyze_report_group`, columns),
	)
	if err := tx.Get(&group, query, key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("unable to query analyzer reports group by key %s: %w", key, err)
	}

	return &group, nil
}

// GetOrCreateAnalyzeReportGroup is similar to GetAnalyzeReportGroup, but it also creates
// an entry if one not exist in the table.
//
// The rows are write-locks as part of `tx` transaction. To unlock the rows either Commit or Rollback
// the transaction.
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//
//	management of metadata in MySQL and data in BlobStorage for firmware images. All the rest
//	entities should not be accessed through Storage. Otherwise locking, transactions and other
//	usual stuff is pretty cludgy (e.g. see the `tx` which semantically partially duplicates `stor.DB`).
func (stor *Storage) GetOrCreateAnalyzeReportGroup(
	ctx context.Context,
	key models.AnalyzeReportGroupKey,
	tx *sqlx.Tx,
	fetchAnalyzeReports bool,
) (
	*models.AnalyzeReportGroup,
	error,
) {
	if key.IsZero() {
		return nil, fmt.Errorf("the provided key is the zero value")
	}

	group, err := stor.GetAnalyzeReportGroup(ctx, key, tx, fetchAnalyzeReports)
	if err != nil {
		return nil, fmt.Errorf("unable to try to fetch an existing analyze report group: %w", err)
	}

	if group != nil {
		return group, nil
	}

	query := "INSERT INTO `analyze_report_group` SET `group_key` = ?"
	if _, err := tx.Exec(query, key); err != nil {
		return nil, fmt.Errorf("unable to create an analyzer reports group with key %s using query '%s': %w", key, query, err)
	}

	group, err = stor.GetAnalyzeReportGroup(ctx, key, tx, fetchAnalyzeReports)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch back the analyze report group: %w", err)
	}
	if group == nil {
		return nil, fmt.Errorf("internal error: we just inserted an analyze group, but it is not there")
	}

	return group, nil
}

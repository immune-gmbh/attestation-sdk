package models

import (
	"time"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

// AnalyzeReport represents a full report for a single analysis
type AnalyzeReport struct {

	// == Direct data ==

	// ID is just the primary key. It is used to reference to from the `analyzer_report` table.
	ID uint64 `db:"id"`

	// JobID is the ID of the job which initiated the analysis. Used for searching
	// for results.
	JobID types.JobID `db:"job_id"`

	// AssetID is an optional field that represents a host which was analyzed
	AssetID *int64 `db:"asset_id"`

	// Timestamp defines the time moment when the analysis report was requested
	Timestamp time.Time `db:"timestamp"`

	// ProcessedAt defines the time moment when the analysis report was processed
	ProcessedAt time.Time `db:"processed_at"`

	// GroupKey is the key used to aggregate multiple reports together.
	//
	// Is assigned by an application which decides how to group reports,
	// currently it is firmware-alerter.
	GroupKey AnalyzeReportGroupKey `db:"group_key"`

	// == Connected data (stored in other tables) ==

	// AnalyzerReports is a list of succeeded analysis reports
	AnalyzerReports []AnalyzerReport `db:"-"`
}

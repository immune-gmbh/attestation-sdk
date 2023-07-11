package models

import (
	"github.com/immune-gmbh/attestation-sdk/pkg/types"
)

// AnalyzeReportGroupKey is an unique key used to aggregate multiple AnalyzeReport-s.
//
// Currently the "ActualImageID" is used for that, so the type is aliased to types.ImageID,
// but feel free to change that.
type AnalyzeReportGroupKey = types.ImageID

// AnalyzeReportGroup represents a group of AnalyzeReports, grouped by `Key`.
type AnalyzeReportGroup struct {

	// == Direct data ==

	// GroupKey is the primary key and the reference to `analyze_report`.`group_key`.
	GroupKey AnalyzeReportGroupKey `db:"group_key"`

	// The ID of the post which represents this group of reports (aggregated by `ReportKey`).
	PostID *int64 `db:"post_id"`

	// The ID of the task (currently, for PWM) which represents this group of reports (aggregated by `ReportKey`).
	TaskID *int64 `db:"task_id"`

	// == Connected data (stored in other tables) ==

	// AnalyzeReports is the list of AnalyzeReports` associated with this group.
	AnalyzeReports []AnalyzeReport `db:"-"`
}

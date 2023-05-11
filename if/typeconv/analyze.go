package typeconv

import (
	"errors"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/analyzerreport"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/apcbsectokens/report/apcbsecanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/biosrtmvolume/report/biosrtmanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/pspsignature/report/pspsignanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/diffanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm/report/intelacmanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/reproducepcr/report/reproducepcranalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	controllererrors "github.com/immune-gmbh/AttestationFailureAnalysisService/server/controller/errors"
)

const (
	maxOptionalInputSize = 1 << 20
)

// ToThriftAnalyzeReport converts internal storage.AnalyzeReport structure to the Thrift representation of it.
func ToThriftAnalyzeReport(report *models.AnalyzeReport) *afas.AnalyzeResult_ {
	result := &afas.AnalyzeResult_{
		JobID:   report.JobID[:],
		Results: make([]*afas.AnalyzerResult_, 0, len(report.AnalyzerReports)),
	}
	for _, report := range report.AnalyzerReports {
		result.Results = append(result.Results, ToThriftAnalyzerReport(report))
	}
	return result
}

// ToThriftAnalysisIssue converts internal analysis.Issue structure to the Thrift representation of it.
func ToThriftAnalysisIssue(issue analysis.Issue) (*analyzerreport.Issue, error) {
	var result analyzerreport.Issue
	if issue.Custom != nil {
		return nil, fmt.Errorf("unknown issue.Custom field's type %T", issue.Custom)
	}

	if len(issue.Description) > 0 {
		result.SetDescription(&issue.Description)
	}

	severity, err := ToThriftAnalysisSeverity(issue.Severity)
	result.SetSeverity(severity)
	return &result, err
}

// ToThriftAnalyzerReport converts internal storage.AnalyzerResult structure to the Thrift representation of it.
func ToThriftAnalyzerReport(report models.AnalyzerReport) *afas.AnalyzerResult_ {
	// note: inputJSON is not mandatory to fill in the result
	inputJSON, err := report.Input.MarshalJSON()
	if err != nil {
		// TODO: print a warning
		_ = err
	}
	if len(inputJSON) > maxOptionalInputSize {
		inputJSON = nil
	}
	result := &afas.AnalyzerResult_{
		AnalyzerName:       string(report.AnalyzerID),
		AnalyzerOutcome:    &afas.AnalyzerOutcome{},
		ProcessedInputJSON: &[]string{string(inputJSON)}[0],
	}
	outcome := result.AnalyzerOutcome
	if err := report.ExecError.Err; err != nil {
		outcome.Err = &afas.Error_{
			ErrorClass:  analyzeExecErrorToClass(err),
			Description: err.Error(),
		}
		return result
	}

	if report.Report == nil {
		return result
	}
	outcome.Report = &analyzerreport.AnalyzerReport{}

	outcome.Report.SetComments(report.Report.Comments)

	if report.Report.Custom != nil {
		var reportInfo analyzerreport.ReportInfo
		switch v := report.Report.Custom.(type) {
		case diffanalysis.CustomReport:
			reportInfo.SetDiffMeasuredBoot(&v)
		case reproducepcranalysis.CustomReport:
			reportInfo.SetReproducePCR(&v)
		case intelacmanalysis.IntelACMDiagInfo:
			reportInfo.SetIntelACM(&v)
		case pspsignanalysis.CustomReport:
			reportInfo.SetPSPSignature(&v)
		case biosrtmanalysis.CustomReport:
			reportInfo.SetBIOSRTMVolume(&v)
		case apcbsecanalysis.CustomReport:
			reportInfo.SetAPCBSecurityTokens(&v)
		default:
			outcome.Report = nil
			outcome.Err = &afas.Error_{
				ErrorClass:  afas.ErrorClass_InternalError,
				Description: fmt.Sprintf("unknown report.Custom field's type %T", report.Report.Custom),
			}
			return result
		}
		outcome.Report.SetCustom(&reportInfo)
	}

	for _, issue := range report.Report.Issues {
		analyzerIssue, err := ToThriftAnalysisIssue(issue)
		if err != nil {
			outcome.Report.Issues = append(outcome.Report.Issues, &analyzerreport.Issue{
				Severity:    analyzerreport.Severity_SeverityWarning,
				Description: &[]string{err.Error()}[0],
			})
		}
		if issue.Custom != nil {
			panic("not supported, yet") // better to terminate the error into a logger, but it is not available here.
		}
		outcome.Report.Issues = append(outcome.Report.Issues, analyzerIssue)
	}

	return result
}

// ToThriftAnalysisSeverity converts internal analysis.Severity structure to the Thrift representation of it.
func ToThriftAnalysisSeverity(severity analysis.Severity) (analyzerreport.Severity, error) {
	switch severity {
	case analysis.SeverityCritical:
		return analyzerreport.Severity_SeverityCritical, nil
	case analysis.SeverityWarning:
		return analyzerreport.Severity_SeverityWarning, nil
	case analysis.SeverityInfo:
		return analyzerreport.Severity_SeverityInfo, nil
	}
	return analyzerreport.Severity_SeverityCritical, fmt.Errorf("unknown severity %d", severity)
}

func analyzeExecErrorToClass(err error) afas.ErrorClass {
	switch {
	case errors.As(err, &controllererrors.ErrUnknownAnalyzer{}) ||
		errors.As(err, &controllererrors.ErrInvalidInput{}) ||
		errors.As(err, &analysis.ErrMissingInput{}):
		return afas.ErrorClass_InvalidInput
	case errors.As(err, &analysis.ErrNotApplicable{}):
		return afas.ErrorClass_NotSupported
	}
	return afas.ErrorClass_InternalError
}

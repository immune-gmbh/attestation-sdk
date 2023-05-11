include "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/apcbsectokens/report/apcbsecanalysis.thrift"
include "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/biosrtmvolume/report/biosrtmanalysis.thrift"
include "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/pspsignature/report/pspsignanalysis.thrift"
include "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/diffanalysis.thrift"
include "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm/report/intelacmanalysis.thrift"
include "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/reproducepcr/report/reproducepcranalysis.thrift"

namespace go immune.AttestationFailureAnalysisService.if.analyzerreport
namespace py immune.AttestationFailureAnalysisService.analyzerreport
namespace py3 immune.AttestationFailureAnalysisService
namespace cpp2 immune.AttestationFailureAnalysisService

enum Severity {
  SeverityUnknown = 0,
  SeverityInfo = 1,
  SeverityWarning = 2,
  SeverityCritical = 3,
}

// IssueInfo provides an ability to customise Issue by analyzers
union IssueInfo {}

// Issue describes a single found problem in firmware
struct Issue {
  // Custom is a custom information provided for issue description
  1: optional IssueInfo Custom;

  // Severity tells how important is found issue
  2: Severity Severity;

  // Description is a text description of a found problem
  3: optional string Description;
}

// ReportInfo provides an ability to customise Report by analyzers
union ReportInfo {
  1: diffanalysis.CustomReport DiffMeasuredBoot;
  2: intelacmanalysis.IntelACMDiagInfo IntelACM;
  3: reproducepcranalysis.CustomReport ReproducePCR;
  4: pspsignanalysis.CustomReport PSPSignature;
  5: biosrtmanalysis.CustomReport BIOSRTMVolume;
  6: apcbsecanalysis.CustomReport APCBSecurityTokens;
}

struct AnalyzerReport {
  // Custom is a custom information provided for Report description
  1: optional ReportInfo Custom;

  2: optional list<Issue> Issues;

  3: optional list<string> Comments;
}

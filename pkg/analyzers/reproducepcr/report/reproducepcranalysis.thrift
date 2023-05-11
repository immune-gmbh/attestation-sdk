include "../../../../if/measurements.thrift"

namespace go immune.AttestationFailureAnalysisService.pkg.analyzers.reproducepcr.report.reproducepcranalysis
namespace py immune.AttestationFailureAnalysisService.reproducepcr.reproducepcranalysis
namespace py3 immune.AttestationFailureAnalysisService.reproducepcr
namespace cpp2 immune.AttestationFailureAnalysisService.reproducepcr

const string ReproducePCRAnalyzerID = "ReproducePCR";

struct CustomReport {
  // TODO: separate: "Expected*" and "Matched*" (right now everything is mixed up in "Expected*")
  1: measurements.Flow ExpectedFlow;
  2: byte ExpectedLocality;
  3: optional binary ExpectedACMPolicyStatus;
  4: list<string> DisabledMeasurements;
}

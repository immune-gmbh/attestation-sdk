include "../../../../if/measurements.thrift"

namespace go pkg.analyzers.reproducepcr.report.generated.reproducepcranalysis

const string ReproducePCRAnalyzerID = "ReproducePCR";

struct CustomReport {
  // TODO: separate: "Expected*" and "Matched*" (right now everything is mixed up in "Expected*")
  1: measurements.Flow ExpectedFlow;
  2: byte ExpectedLocality;
  3: optional binary ExpectedACMPolicyStatus;
  4: list<string> DisabledMeasurements;
}

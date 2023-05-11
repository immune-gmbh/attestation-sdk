namespace go immune.AttestationFailureAnalysisService.pkg.analyzers.intelacm.report.intelacmanalysis
namespace py immune.AttestationFailureAnalysisService.intelacm.intelacmanalysis
namespace py3 immune.AttestationFailureAnalysisService.intelacm
namespace cpp2 immune.AttestationFailureAnalysisService.intelacm

const string IntelACMAnalyzerID = "IntelACM";

struct ACMInfo {
  1: i32 Date;
  2: i16 SESVN;
  3: i16 TXTSVN;
// Signature verification is blocked by: https://premiersupport.intel.com/IPS/5003b00001cnlpi
//4: bool SignatureIsValid
}

struct IntelACMDiagInfo {
  1: optional ACMInfo Original;
  2: optional ACMInfo Received;
}

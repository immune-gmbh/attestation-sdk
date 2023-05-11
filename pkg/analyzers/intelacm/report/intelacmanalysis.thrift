namespace go pkg.analyzers.intelacm.report.generated.intelacmanalysis

const string IntelACMAnalyzerID = "IntelACM";

struct ACMInfo {
  1: i32 Date;
  2: i16 SESVN;
  3: i16 TXTSVN;
// Unclear how to verify the signature
//4: bool SignatureIsValid
}

struct IntelACMDiagInfo {
  1: optional ACMInfo Original;
  2: optional ACMInfo Received;
}

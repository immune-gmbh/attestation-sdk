namespace go immune.AttestationFailureAnalysisService.pkg.analyzers.amd.pspsignature.report.pspsignanalysis
namespace py immune.AttestationFailureAnalysisService.pspsignature.pspsignanalysis
namespace py3 immune.AttestationFailureAnalysisService.pspsignature
namespace cpp2 immune.AttestationFailureAnalysisService.pspsignature

include "../../types/psptypes.thrift"

const string PSPSignatureAnalyzerID = "PSPSignature";

enum Validation {
  Unknown = 0,
  NotFound = 1, // this item is crucial to firmware. Optional items are not reported
  InvalidFormat = 2, // means that structure of an item is broken (usually PSPHeader)
  KeyNotFound = 3, // a key used to verify signature was not found
  IncorrectSignature = 4, // a signature didn't match a key
  Correct = 5, // item's signature is correct
}

struct ValidatedItem {
  1: psptypes.DirectoryType Directory;
  2: optional psptypes.DirectoryEntry Entry; // is not set if item is a directory
  3: Validation ValidationResult;
  4: string ValidationDescription;
}

struct CustomReport {
  1: list<ValidatedItem> Items;
}

namespace go immune.AttestationFailureAnalysisService.if.measurements
namespace py immune.AttestationFailureAnalysisService.measurements
namespace py3 immune.AttestationFailureAnalysisService
namespace cpp2 immune.AttestationFailureAnalysisService

enum Flow {
  AUTO = 0,
  INTEL_LEGACY_TXT_DISABLED = 1,
  INTEL_LEGACY_TXT_ENABLED = 2,
  INTEL_CBNT0T = 3,
  INTEL_LEGACY_TPM12_TXT_ENABLED = 4,
  AMD_MILAN_LEGACY_LOCALITY_0 = 5,
  AMD_MILAN_LEGACY_LOCALITY_3 = 6,
  AMD_MILAN_LOCALITY_0 = 7,
  AMD_MILAN_LOCALITY_3 = 8,
  AMD_GENOA_LOCALITY_0 = 9,
  AMD_GENOA_LOCALITY_3 = 10,
}

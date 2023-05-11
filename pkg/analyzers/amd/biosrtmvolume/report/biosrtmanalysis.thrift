namespace go immune.AttestationFailureAnalysisService.pkg.analyzers.amd.biosrtmvolume.report.biosrtmanalysis
namespace py immune.AttestationFailureAnalysisService.biosrtmvolume.biosrtmanalysis
namespace py3 immune.AttestationFailureAnalysisService.biosrtmvolume
namespace cpp2 immune.AttestationFailureAnalysisService.biosrtmvolume

const string BIOSRTMVolumeAnalyzerID = "BIOSRTMVolume";

enum Validation {
  Unknown = 0,
  CorrectSignature = 1, // BIOS RTM Volume exists and is correctly signed
  RTMVolumeNotFound = 2, // BIOS RTM Volume entry is not found
  RTMSignatureNotFound = 3, // BIOS RTM Signature entry is not found
  PSBDisabled = 5, // PSB disabled firmware
  InvalidFormat = 6, // means that structure of an item is broken
  IncorrectSignature = 7, // a signature didn't match a key
}

struct PlatformBindingInfo {
  1: i16 VendorID; // VendorID is 1 byte long, but thrift makes it signed which leads to warnings in typed languates
  2: byte KeyRevisionID;
  3: byte PlatformModelID;
}

struct SecurityFeatureVector {
  1: bool DisableBIOSKeyAntiRollback;
  2: bool DisableAMDBIOSKeyUse;
  3: bool DisableSecureDebugUnlock;
}

struct BIOSRTMVolume {
  1: byte BIOSDirectoryLevel;
  2: Validation ValidationResult;
  3: string ValidationDescription;
  4: optional PlatformBindingInfo PlatformInfo;
  5: optional SecurityFeatureVector SecurityFeatures;
}

struct CustomReport {
  1: list<BIOSRTMVolume> Items;
}

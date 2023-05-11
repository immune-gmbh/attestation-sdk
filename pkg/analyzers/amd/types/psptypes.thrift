namespace go immune.AttestationFailureAnalysisService.pkg.analyzers.amd.types.psptypes
namespace py immune.AttestationFailureAnalysisService.psptypes
namespace py3 immune.AttestationFailureAnalysisService
namespace cpp2 immune.AttestationFailureAnalysisService

enum DirectoryType {
  PSPTableLevel1 = 0,
  PSPTableLevel2 = 1,
  BIOSTableLevel1 = 2,
  BIOSTableLevel2 = 3,
}

enum PSPDirectoryTableEntryType {
  AMDPublicKeyEntry = 0,
  PSPBootloaderFirmwareEntry = 1, // 0x01
  PSPRecoveryBootlader = 3, // 0x03
  SMUOffChipFirmwareEntry = 8, // 0x08
  ABLPublicKey = 10, // 0x0A
  SMUOffChipFirmware2Entry = 18, // 0x12
  UnlockDebugImageEntry = 19, // 0x13
  SecurityPolicyBinaryEntry = 36, // 0x24
  MP5FirmwareEntry = 42, //  0x2A
  AGESABinary0Entry = 48, // 0x30
  SEVCodeEntry = 57, // 0x39
  PSPDirectoryTableLevel2Entry = 64, // 0x40
  DXIOPHYSRAMFirmwareEntry = 66, // 0x42
  DRTMTAEntry = 71, // 0x47
  KeyDatabaseEntry = 80, // 0x50
}

enum BIOSDirectoryTableEntryType {
  BIOSRTMSignatureEntry = 7, // 0x07
  APCBDataEntry = 96, // 0x60
  APOBBinaryEntry = 97, // 0x61
  BIOSRTMVolumeEntry = 98, // 0x62
  PMUFirmwareInstructionsEntry = 100, // 0x64
  PMUFirmwareDataEntry = 101, // 0x65
  MicrocodePatchEntry = 102, // 0x66
  APCBDataBackupEntry = 104, // 0x68
  VideoInterpreterEntry = 105, // 0x69
  BIOSDirectoryTableLevel2Entry = 106, // 0x70
}

struct BIOSDirectoryEntry {
  1: BIOSDirectoryTableEntryType Entry;
  2: i16 Instance;
}

union DirectoryEntry {
  1: PSPDirectoryTableEntryType PSPEntry;
  2: BIOSDirectoryEntry BIOSEntry;
}

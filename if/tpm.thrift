namespace go immune.AttestationFailureAnalysisService.if.tpm
namespace py immune.AttestationFailureAnalysisService.tpm
namespace py3 immune.AttestationFailureAnalysisService
namespace cpp2 immune.AttestationFailureAnalysisService

struct EventLog {
  1: list<Event> Events;
}

struct Event {
  1: i64 PCRIndex;
  2: EventType Type;
  3: binary Data;
  4: Digest_ Digest;
}

// we add the underscore in the end to workaround problems in py3
struct Digest_ {
  1: Algo HashAlgo;
  2: binary Digest;
}

typedef i64 EventType

// Have to declare as `const` instead of `enum`, because otherwise I get
// an error that the values are truncated.
const EventType EV_PREBOOT_CERT = 0x00000000;
const EventType EV_POST_CODE = 00000001;
const EventType EV_UNUSED = 0x00000002;
const EventType EV_NO_ACTION = 0x00000003;
const EventType EV_SEPARATOR = 0x00000004;
const EventType EV_ACTION = 0x00000005;
const EventType EV_EVENT_TAG = 0x00000006;
const EventType EV_S_CRTM_CONTENTS = 0x00000007;
const EventType EV_S_CRTM_VERSION = 0x00000008;
const EventType EV_CPU_MICROCODE = 0x00000009;
const EventType EV_PLATFORM_CONFIG_FLAGS = 0x0000000A;
const EventType EV_TABLE_OF_DEVICES = 0x0000000B;
const EventType EV_COMPACT_HASH = 0x0000000C;
const EventType EV_IPL = 0x0000000D;
const EventType EV_IPL_PARTITION_DATA = 0x0000000E;
const EventType EV_NONHOST_CODE = 0x0000000F;
const EventType EV_NONHOST_CONFIG = 0x00000010;
const EventType EV_NONHOST_INFO = 0x00000011;
const EventType EV_OMIT_BOOT_DEVICE_EVENTS = 0x00000012;
const EventType EV_EFI_EVENT_BASE = 0x80000000;
const EventType EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001;
const EventType EV_EFI_VARIABLE_BOOT = 0x80000002;
const EventType EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003;
const EventType EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004;
const EventType EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005;
const EventType EV_EFI_GPT_EVENT = 0x80000006;
const EventType EV_EFI_ACTION = 0x80000007;
const EventType EV_EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008;
const EventType EV_EFI_HANDOFF_TABLES = 0x80000009;
const EventType EV_EFI_HCRTM_EVENT = 0x80000010;
const EventType EV_EFI_VARIABLE_AUTHORITY = 0x800000E0;

enum Algo {
  Error = 0x0000,
  RSA = 0x0001,
  SHA1 = 0x0004,
  SHA256 = 0x000B,
  SHA384 = 0x000C,
  SHA512 = 0x000D,
  NULL_ = 0x0010, // we add the underscore in the end to workaround problems in py3
  SM3_256 = 0x0012,
  SM4 = 0x0013,
  RSASSA = 0x0014,
  ECDSA = 0x0018,
  SM2 = 0x001B,
  KDF2 = 0x0021,
  ECC = 0x0023,
}

struct Version {
  1: byte Major;
  2: byte Minor;
}

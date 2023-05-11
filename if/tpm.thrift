// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
namespace go if.generated.tpm

struct EventLog {
  1: list<Event> Events;
}

struct Event {
  1: i8 PCRIndex;
  2: i32 Type;
  3: binary Data;
  4: Digest_ Digest;
}

// we add the underscore in the end to workaround problems in py3
struct Digest_ {
  1: Algo HashAlgo;
  2: binary Digest;
}

// Have to declare as `const` instead of `enum`, because otherwise I get
// an error that the values are truncated.
const i64 EV_PREBOOT_CERT = 0x00000000;
const i64 EV_POST_CODE = 00000001;
const i64 EV_UNUSED = 0x00000002;
const i64 EV_NO_ACTION = 0x00000003;
const i64 EV_SEPARATOR = 0x00000004;
const i64 EV_ACTION = 0x00000005;
const i64 EV_EVENT_TAG = 0x00000006;
const i64 EV_S_CRTM_CONTENTS = 0x00000007;
const i64 EV_S_CRTM_VERSION = 0x00000008;
const i64 EV_CPU_MICROCODE = 0x00000009;
const i64 EV_PLATFORM_CONFIG_FLAGS = 0x0000000A;
const i64 EV_TABLE_OF_DEVICES = 0x0000000B;
const i64 EV_COMPACT_HASH = 0x0000000C;
const i64 EV_IPL = 0x0000000D;
const i64 EV_IPL_PARTITION_DATA = 0x0000000E;
const i64 EV_NONHOST_CODE = 0x0000000F;
const i64 EV_NONHOST_CONFIG = 0x00000010;
const i64 EV_NONHOST_INFO = 0x00000011;
const i64 EV_OMIT_BOOT_DEVICE_EVENTS = 0x00000012;
const i64 EV_EFI_EVENT_BASE = 0x80000000;
const i64 EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001;
const i64 EV_EFI_VARIABLE_BOOT = 0x80000002;
const i64 EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003;
const i64 EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004;
const i64 EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005;
const i64 EV_EFI_GPT_EVENT = 0x80000006;
const i64 EV_EFI_ACTION = 0x80000007;
const i64 EV_EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008;
const i64 EV_EFI_HANDOFF_TABLES = 0x80000009;
const i64 EV_EFI_HCRTM_EVENT = 0x80000010;
const i64 EV_EFI_VARIABLE_AUTHORITY = 0x800000E0;

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

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

namespace go pkg.analyzers.amd.types.generated.psptypes

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

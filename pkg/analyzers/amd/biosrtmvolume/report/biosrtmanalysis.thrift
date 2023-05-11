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

namespace go pkg.analyzers.amd.biosrtmvolume.report.generated.biosrtmanalysis

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

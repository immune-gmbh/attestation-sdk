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

namespace go pkg.analyzers.diffmeasuredboot.report.generated.diffanalysis

const string DiffMeasuredBootAnalyzerID = "DiffMeasuredBoot";

enum DiffDiagnosis {
  Undefined = 0,
  Match = 1,
  UnsuspiciousDamage = 2,
  SuspiciousDamage = 3,
  FirmwareVersionMismatch = 4,
  InvalidOriginalFirmware = 5,
  KnownTamperedHost = 6,
}

struct NodeInfo {
  1: string UUID;
  2: optional string Description;
}

// TODO: Rename back to "Range". It was renamed due to a bug in Thrift-generator of "py3-types__cython".
struct Range_ {
  1: i64 Offset;
  2: i64 Length;
}

union RangeOrForcedData {
  1: Range_ Range;
  2: binary ForceData;
}

struct DataChunk {
  1: string ID;
  2: RangeOrForcedData Data;
}

struct Measurement {
  1: string ID;
  2: list<DataChunk> DataChunks;
}

struct RelatedMeasurement {
  1: Measurement Measurement;
  2: list<DataChunk> RelatedDataChunks;
}

struct DiffEntry {
  // TODO: Remove this, use `Range` instead of `Start` and `Length` directly:
  1: i64 OBSOLETE_Start;
  2: i64 OBSOLETE_Length;

  // HammingDistance is a bit-wise hamming distance between the data blocks.
  3: i64 HammingDistance;
  // HammingDistanceNon00orFF is a bit-wise hamming distance between the data
  // blocks, excluding bytes 0x00 and 0xff
  4: i64 HammingDistanceNon00orFF;

  5: Range_ Range;
  6: list<RelatedMeasurement> RelatedMeasurements;
  7: list<NodeInfo> Nodes;
}

struct CustomReport {
  1: DiffDiagnosis Diagnosis;
  2: list<DiffEntry> DiffEntries;

  // ImageOffset is the offset used to align the actual and the original images:
  // AddressInOriginalImage = AddressInActualImage + ImageOffset
  3: i64 ImageOffset;
}

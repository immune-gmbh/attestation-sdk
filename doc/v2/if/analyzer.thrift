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

include "../../../if/caching_policy.thrift"
include "../../../if/tpm.thrift"

namespace go doc.v2.if.generated.analyzer

struct NodeInfo {
    1: string UUID
    2: optional string Description
}

struct DiffEntry {
    1: i64 Offset;
    2: i64 Length;
    3: i64 HammingDistance;
    4: string RelatedMeasurements;
    5: list<NodeInfo> Nodes;
}

struct StatusRegister {
    1: string id;
    2: binary value;
}

enum TPMType {
    UNKNOWN = 0,
    TPM12 = 1,
    TPM20 = 2,
}

enum Flow {
    AUTO = 0,
    INTEL_LEGACY_TXT_DISABLED = 1,
    INTEL_LEGACY_TXT_ENABLED = 2,
    INTEL_CBNT0T = 3,
    INTEL_LEGACY_TPM12_TXT_ENABLED = 4,
    AMD_LEGACY_LOCALITY_0 = 5,
    AMD_LEGACY_LOCALITY_3 = 6,
    AMD_LOCALITY_0 = 7,
    AMD_LOCALITY_3 = 8,
}

enum DiffDiagnosis {
    Undefined = 0
    Match = 1,
    UnsuspiciousDamage = 2,
    SuspiciousDamage = 3,
    FirmwareVersionMismatch = 4,
    InvalidOriginalFirmware = 5,
    KnownTamperedHost = 6,
}

struct ACMInfo {
    1: i32 Date
    2: i16 SESVN
    3: i16 TXTSVN
    // Signature verification is blocked by: https://premiersupport.intel.com/IPS/5003b00001cnlpi
    //4: bool SignatureIsValid
}

struct HostInfo {
    1: optional string Hostname;
    2: optional i64 AssetID;
    3: optional string SerialNumber;
    4: optional i32 ModelID;
    5: bool IsVerified = false;
}

struct AnalyzeFirmwareRequest {
    // HostInfo contains information about the host (to be used for logging and alerts).
    1: optional HostInfo HostInfo

    // Tags is a list of custom tags (to be used in logged reports and alerts).
    2: optional list<string> Tags

    // Artifacts contains reusable (for multiple analyses) blobs, like a firmware image.
    //
    // In an analysis these artifacts are referenced by their index in this list.
    3: list<binary> Artifacts

    // AnalysisList is the actual list of analyses/checks/tests/validations to be performed.
    4: list<AnalyzeFirmwareRequestItem> AnalysisList
}

// AnalyzerID is an unique identifier of each analysis/check/test/validation.
enum AnalyzerID {
    // DiffMeasuredBootAreas compares essential for measured boot areas between
    // the provided firmware and the original one.
    DiffMeasuredBootAreas = 1

    // CompareEventLogAndRealMeasurements replays EventLog and validates if the
    // final PCR values are the same as the provided.
    CompareEventLogAndRealMeasurements = 2

    // ValidateMeasurementsFlow analyzies which measurement flow the image should
    // have and tries to guess which measurement flow it actually is given
    // final PCR values.
    ValidateMeasurementsFlow = 3

    // ValidateImageIntelCBnTManifestsAndACM validates CBnT manifests and the Intel ACM.
    ValidateImageIntelCBnTManifestsAndACM = 4
}

// AnalyzeFirmwareRequestItem is a single item of AnalyzeFirmwareRequest.AnalysisList
struct AnalyzeFirmwareRequestItem {
    // AnalysisRequestID is just an arbitrary ID at client's discetion to find the result
    // of this request in the list of reports.
    1: optional binary AnalysisRequestID

    // AnalyzerID defines which analyzer to use
    2: AnalyzerID AnalyzerID

    // Input provides the input for the analyzer
    3: AnalysisInput Input

    // CachingPolicy defines if cache should be used.
    //4: caching_policy.CachingPolicy CachingPolicy
}

struct AnalyzeFirmwareResult {
    1: list<AnalyzeFirmwareResultItem> List
}

// AnalyzeFirmwareResultItem is a signle item of AnalyzeFirmwareResult.AnalysisReports
struct AnalyzeFirmwareResultItem {
    // AnalysisRequestID has the same value as in the according AnalyzeFirmwareRequestItem
    1: optional binary AnalysisRequestID

    // AnalyzerID defines which analyzer was used.
    //
    // Always the same value as in the according AnalyzeFirmwareRequestItem.
    2: AnalyzerID AnalyzerID

    // Report is the outcome (except for errors and comments).
    3: AnalysisReport Report

    // Errors is the list of errors.
    4: list<Error> Errors

    // Comments is the list of additional messages, which are not considered errors.
    5: list<string> Comments
}

struct AnalyzeFirmwareJob {
    // ID is an unique job ID, for example a UUID4 value
    1: binary ID

    // Result contains the analysis results that are already completed.
    3: AnalyzeFirmwareResult Result
}

// === auxiliary structures ===

struct PCRValues {
    // Values is a map of PCR index to a map of tpm.Algo to the PCR digest.
    1: map<i64,map<tpm.Algo, binary>> Values
}

// FirmwareReference contains a reference to a dumped firmware image.
union FirmwareReference {
    1: i64 ArtifactIndex
    2: binary ManifoldImageID
}

// OriginalFirmwareSelector allows to select which firmware from RTP Firmware Table will
// be used as the original one.
union OriginalFirmwareSelector {
    1: FirmwareVersionAndDate VersionAndDate

    // Tarball is an optional way to specify an exactly firmware tarball by user
    // they wants to compare against.
    2: string Tarball
}

struct FirmwareVersionAndDate {
    1: string Version
    2: string ReleaseDate
    3: optional i64 ModelID
}

enum ErrorClass {
    InternalError = 1
    InvalidInput = 2
    NotSupported = 3
    InsecureConfiguration = 4
    InvalidSignature = 5
}

struct Error {
    1: ErrorClass ErrorClass
    2: i64 Code
    3: string Description
}

// === analyzer-specific structures ===

// AnalysisInput is analysis-specific input data.
// TODO: Use analyzer-agnostic data k/v list
union AnalysisInput {
    1: DiffMeasuredBootAreasInput DiffMeasuredBootAreas
    2: CompareEventLogAndRealMeasurementsInput CompareEventLogAndRealMeasurements
    3: ValidateMeasurementsFlowInput ValidateMeasurementsFlow
    4: ValidateImageIntelCBnTManifestsAndACMInput ValidateImageIntelCBnTManifestsAndACM
}

// AnalysisReport is analysis-specific output data.
union AnalysisReport {
    1: DiffMeasuredBootAreasReport DiffMeasuredBootAreas
    2: CompareEventLogAndRealMeasurementsReport CompareEventLogAndRealMeasurements
    3: ValidateMeasurementsFlowReport ValidateMeasurementsFlow
    4: ValidateImageIntelCBnTManifestsAndACMReport ValidateImageIntelCBnTManifestsAndACM
}

struct DiffMeasuredBootAreasInput {
    1: FirmwareReference DumpedFirmware
    2: OriginalFirmwareSelector OriginalFirmware
}

struct DiffMeasuredBootAreasReport {
    1: list<DiffEntry> DiffEntries
    2: DiffDiagnosis DiffDiagnosis
}

struct CompareEventLogAndRealMeasurementsInput {
    1: optional tpm.EventLog TPMEventLog;
    2: PCRValues ExpectedPCRValues
}

struct CompareEventLogAndRealMeasurementsReport {
    // nothing to report, all the analysis outcome
    // is included into AnalyzeFirmwareResultItem.Errors
}

struct ValidateMeasurementsFlowInput {
    1: FirmwareReference Firmware
    2: PCRValues ResultingPCRValues
}

struct ValidateMeasurementsFlowReport {
    1: Flow ExpectedFlow
    2: byte ExpectedLocality
    3: optional Flow ActualFlow
    4: optional byte ActualLocality
    5: list<i64> MissedMeasurements
}

struct ValidateImageIntelCBnTManifestsAndACMInput {
    1: FirmwareReference DumpedFirmware
}

struct ValidateImageIntelCBnTManifestsAndACMReport {
    1: optional ACMInfo ACMInfo
}

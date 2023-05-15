include "analyzerreport.thrift"
include "caching_policy.thrift"
include "measurements.thrift"
include "tpm.thrift"
include "../pkg/analyzers/diffmeasuredboot/report/diffanalysis.thrift"
include "../pkg/analyzers/intelacm/report/intelacmanalysis.thrift"

namespace go if.generated.afas

// TODO: remove these typedef-s, they are set only for backward compatibility
typedef diffanalysis.NodeInfo NodeInfo
typedef diffanalysis.DiffEntry DiffEntry
typedef diffanalysis.RelatedMeasurement RelatedMeasurement
typedef diffanalysis.Measurement Measurement
typedef diffanalysis.DataChunk DataChunk
// TODO: Rename back to "Range". It was renamed due to a bug in Thrift-generator of "py3-types__cython".
typedef diffanalysis.Range_ Range_

struct PCRValue {
  1: optional binary Original;
  2: optional binary Received;
  3: optional binary LastReported;
  4: optional binary EventLog;
  5: optional binary TPM;
  6: optional binary RTPFWTable;
}

struct PCRValues {
  1: optional PCRValue PCR0SHA1;
  2: optional PCRValue PCR0SHA256;
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

enum CompressionType {
  None = 0,
  XZ = 1,
}

enum DataSource {
  RawBlob = 0,
  Manifold = 1,
}

union VendorSpecificDiagInfo {
  1: IntelDiagInfo Intel;
}

struct IntelDiagInfo {
  1: optional intelacmanalysis.IntelACMDiagInfo ACM;
}

struct HostInfo {
  1: optional string Hostname;
  2: optional i64 AssetID;
  3: optional string SerialNumber;
  4: optional i32 ModelID;
  5: bool IsVerified = false;
  6: bool IsClientHostAnalyzed;
}

struct ServerInfo {
  1: string Revision;
  2: BuildMode BuildMode;
}

enum BuildMode {
  Undefined = 0,
  opt = 1,
  dev = 2,
}

exception UnableToGetOriginalFirmware {
  1: string BIOSVersion;
  3: string Reason;
}

exception IncorrectHostConfiguration {
  1: string Reason;
}

struct SearchFirmwareRequest {
  // OrFilters are collected together through OR-s.
  1: list<SearchFirmwareFilters> OrFilters;

  // FetchContent defines if the data/content of images should also
  // be provided with the search results. If false, then Found[*].Data will be
  // null.
  2: bool FetchContent = false;
}

struct SearchFirmwareFilters {
  // Non-empty fields are collected together through AND-s.
  1: optional binary ImageID;
  2: optional binary HashSHA2_512;
  3: optional binary HashBlake3_512;
  4: optional binary HashStable;
  5: optional string Filename;
  6: optional string Version;
}

struct SearchFirmwareResult {
  1: list<Firmware> Found;
}

struct Firmware {
  1: FirmwareImageMetadata Metadata;
  2: optional binary Data;
}

struct FirmwareImageMetadata {
  1: binary ImageID;
  2: binary HashSHA2_512;
  3: binary HashBlake3_512;
  4: binary HashStable;

  5: optional string Filename;
  6: optional string Version;
  7: i64 Size;
  8: i64 TSAdd;
  9: optional i64 TSUpload;
}

struct SearchReportRequest {
  1: list<SearchReportFilters> OrFilters;

  // Limit defines the maximal amount of reports to return.
  // Value "0" means no limit.
  2: i64 Limit;
}

struct SearchReportFilters {
  // Non-empty fields are collected together through AND-s.
  1: optional binary JobID;
  2: optional i64 AssetID;
  3: SearchFirmwareFilters ActualFirmware;
}

struct SearchReportResult {
  1: list<AnalyzeResult> Found;
}

struct FirmwareVersion {
  1: string Version;
}

struct CompressedBlob {
  1: binary Blob;
  2: CompressionType Compression;
}

union FirmwareImage {
  1: CompressedBlob Blob;
  2: string Filename;
  3: binary ManifoldID;
  4: string EverstoreHandle;
  5: FirmwareVersion FwVersion;
}

struct PCR {
  1: binary Value;
  // Index means PCR number: 0, 1, 2, ...
  2: i32 Index;
}

// Artifact represents large shared data objects that are desirable to be passed once
union Artifact {
  1: FirmwareImage FwImage;
  2: PCR Pcr;
  3: TPMType TPMDevice;
  4: tpm.EventLog TPMEventLog;
  5: list<StatusRegister> StatusRegisters;
  6: measurements.Flow MeasurementsFlow;
}

// DiffMeasuredBootInput is an input structure for DiffMeasuredBoot analyzer
struct DiffMeasuredBootInput {
  1: i32 ActualFirmwareImage;
  2: optional i32 OriginalFirmwareImage;
  3: optional i32 StatusRegisters;
  4: optional i32 TPMDevice;
  5: optional i32 TPMEventLog;
  6: optional i32 ActualPCR0;
}

struct IntelACMInput {
  1: i32 ActualFirmwareImage;
  2: optional i32 OriginalFirmwareImage;
}

struct ReproducePCRInput {
  1: i32 ActualFirmwareImage;
  2: optional i32 OriginalFirmwareImage;
  3: optional i32 StatusRegisters;
  4: optional i32 TPMDevice;
  5: optional i32 TPMEventLog;
  6: i32 ExpectedPCR;
  7: optional i32 MeasurementsFlow;
}

struct PSPSignatureInput {
  1: i32 ActualFirmwareImage;
}

struct BIOSRTMVolumeInput {
  1: i32 ActualFirmwareImage;
}

struct APCBSecurityTokensInput {
  1: i32 ActualFirmwareImage;
}

// AnalysisInput is analysis-specific input data.
union AnalyzerInput {
  1: DiffMeasuredBootInput DiffMeasuredBoot;
  2: IntelACMInput IntelACM;
  3: ReproducePCRInput ReproducePCR;
  4: PSPSignatureInput PSPSignature;
  5: BIOSRTMVolumeInput BIOSRTMVolume;
  6: APCBSecurityTokensInput APCBSecurityTokens;
}

struct AnalyzeRequest {
  // HostInfo contains information about the host (to be used for logging and alerts).
  1: optional HostInfo HostInfo;

  // Artifacts contains reusable (for multiple analyses) variables, like a firmware image.
  //
  // In an analysis these artifacts are referenced by their index in this list.
  2: list<Artifact> Artifacts;

  // Analyzers defines input structure for analyzers to be started
  3: list<AnalyzerInput> Analyzers;
}

enum ErrorClass {
  InternalError = 1,
  InvalidInput = 2,
  NotSupported = 3,
}

struct Error {
  1: ErrorClass ErrorClass;
  2: string Description;
}

struct AnalyzerResult {
  1: string AnalyzerName;
  2: AnalyzerOutcome AnalyzerOutcome;

  // For verbosity, logging and debugging on the client side, only.
  // No essential functionality should depend on this.
  // May not be provided if the server decides so for any reason.
  3: optional string ProcessedInputJSON;
}

union AnalyzerOutcome {
  1: analyzerreport.AnalyzerReport Report;
  2: Error Err;
}

struct AnalyzeResult {
  // JobID is a unique identifier for completed analysis. Could be used to find logs
  1: binary JobID;

  // Results are analyzers reports or errors in the same order as in AnalyzeFirmwareRequest
  2: list<AnalyzerResult> Results;
}

struct CheckFirmwareVersionRequest {
  1: list<FirmwareVersion> firmwares;
}

struct CheckFirmwareVersionResult {
  1: list<bool> existStatus;
}

service AttestationFailureAnalyzerService {
  SearchFirmwareResult SearchFirmware(1: SearchFirmwareRequest request);
  SearchReportResult SearchReport(1: SearchReportRequest request);
  AnalyzeResult Analyze(1: AnalyzeRequest request);
  CheckFirmwareVersionResult CheckFirmwareVersion(
    1: CheckFirmwareVersionRequest request,
  );
}

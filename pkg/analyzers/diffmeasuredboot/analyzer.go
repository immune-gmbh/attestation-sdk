package diffmeasuredboot

import (
	"context"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/diffanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/measurements"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/lib/format"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
)

func init() {
	analysis.RegisterType((*diffanalysis.CustomReport)(nil))
}

// ID represents the unique id of DiffMeasuredBoot analyzer
const ID analysis.AnalyzerID = diffanalysis.DiffMeasuredBootAnalyzerID

// NewExecutorInput builds an analysis.Executor's input required for DiffMeasuredBoot analyzer
//
// Optional arguments: tpm, eventlog, actualPCR and enforcedMeasurementsFlow
func NewExecutorInput(
	originalFirmware analysis.Blob,
	actualFirmware analysis.Blob,
	regs registers.Registers,
	tpm tpmdetection.Type, // optional
	eventlog *tpmeventlog.TPMEventLog, // optional
	actualPCR []byte, // optional
	enforcedMeasurementsFlow *pcr.Flow, // optional
) (analysis.Input, error) {
	if originalFirmware == nil || actualFirmware == nil {
		return nil, fmt.Errorf("firmware images should be specified")
	}

	actualRegisters, err := analysis.NewActualRegisters(regs)
	if err != nil {
		return nil, fmt.Errorf("failed to convert registers: %w", err)
	}

	result := analysis.NewInput()
	result.AddOriginalFirmware(
		originalFirmware,
	).AddActualFirmware(
		actualFirmware,
	).AddActualRegisters(
		actualRegisters,
	).AddTPMDevice(
		tpm,
	)
	if eventlog != nil {
		result.AddTPMEventLog(eventlog)
	}
	if len(actualPCR) > 0 {
		result.AddActualPCR0(actualPCR)
	}
	if enforcedMeasurementsFlow != nil {
		result.ForceBootFlow(flows.FromOld(*enforcedMeasurementsFlow))
	}
	return result, nil
}

// Input describes the input data for the DiffMeasuredBoot analyzer
type Input struct {
	ActualFirmware   analysis.ActualFirmwareBlob
	OriginalFirmware analysis.OriginalFirmware
	ActualBIOSInfo   *analysis.ActualBIOSInfo   `exec:"optional"`
	OriginalBIOSInfo *analysis.OriginalBIOSInfo `exec:"optional"`
	AlignedOrigFW    analysis.AlignedOriginalFirmware
	StatusRegisters  analysis.FixedRegisters
	BootFlow         types.BootFlow
	HostAssetID      *analysis.AssetID `exec:"optional"`
}

// DiffMeasuredBoot represents the analyzer
type DiffMeasuredBoot struct {
}

// New creates a new instance of DiffMeasuredBoot
func New() analysis.Analyzer[Input] {
	return &DiffMeasuredBoot{}
}

// ID implements the ID method required for analysis.Analyzer
func (analyzer *DiffMeasuredBoot) ID() analysis.AnalyzerID {
	return "DiffMeasuredBoot"
}

// TODO: create a dedicated package `typeconv` for conversions to Thrift and back
func convDataChunk(chunk *diff.DataChunk) *diffanalysis.DataChunk {
	if chunk == nil {
		return nil
	}
	convChunk := &diffanalysis.DataChunk{
		ID:   chunk.Description,
		Data: &diffanalysis.RangeOrForcedData{},
	}
	if chunk.ForceBytes != nil {
		convChunk.Data.SetForceData(chunk.ForceBytes)
	} else {
		convChunk.Data.SetRange(&diffanalysis.Range_{
			Offset: int64(chunk.Reference.Offset),
			Length: int64(chunk.Reference.Length),
		})
	}

	return convChunk
}

// Analyze makes the difference analysis of firmwares
func (analyzer *DiffMeasuredBoot) Analyze(ctx context.Context, input Input) (*analysis.Report, error) {

	// == getting the measurements ==

	origBIOSImg := biosimage.NewFromParsed(input.OriginalFirmware.UEFI())
	bootResult := measurements.SimulateBootProcess(
		ctx,
		origBIOSImg,
		input.StatusRegisters.GetRegisters(),
		bootflowtypes.Flow(input.BootFlow),
	)
	if err := bootResult.Log.Error(); err != nil {
		return nil, fmt.Errorf("unable to simulate a boot process: %w", err)
	}

	// == getting the reference ranges with offset aligned with the actual firmware ==

	measurements := bootResult.CurrentState.MeasuredData
	refs := measurements.References().BySystemArtifact(origBIOSImg)
	actualBIOSImg := biosimage.New(input.ActualFirmware.Bytes())
	for idx := range refs {
		ref := &refs[idx]
		if ref.AddressMapper != (biosimage.PhysMemMapper{}) {
			// This trick below with changing the Artifact value works only if the AddressMapper is PhysMemMapper.
			// TODO: use a more robust aligning mechanism.
			return nil, fmt.Errorf("internal error: it is expected that the references are defined through PhysMemMapper, but it has %T instead", ref.AddressMapper)
		}
		ref.Artifact = actualBIOSImg
	}
	if err := refs.Resolve(); err != nil {
		return nil, fmt.Errorf("unable to resolve the references to measured data: %w", err)
	}
	refs.SortAndMerge()

	// == analyzing ==

	result := &analysis.Report{}

	alignedOrigFW := input.AlignedOrigFW.UEFI()
	diffEntries := diff.Diff(refs.Ranges(), alignedOrigFW.Buf(), input.ActualFirmware.Bytes(), nil)
	diffEntries.SortAndMerge()

	report := diff.Analyze(diffEntries, measurementsForDiffAnalysis(bootResult.Log), alignedOrigFW, input.ActualFirmware.Bytes())
	diagnosis := Diagnose(
		logger.FromCtx(ctx),
		report.Entries.DiffRanges(),
		alignedOrigFW,
		input.ActualFirmware,
		input.ActualBIOSInfo,
		input.OriginalBIOSInfo,
	)

	// == compiling the report ==

	customReport := diffanalysis.CustomReport{
		// TODO: consider deleting this line:
		ImageOffset: int64(input.AlignedOrigFW.ImageOffset),
	}
	// TODO: move this conversion to Thrift to a dedicated package (and name it "typeconv").
	for _, diffEntry := range report.Entries {
		convEntry := &diffanalysis.DiffEntry{
			Range: &diffanalysis.Range_{
				Offset: int64(diffEntry.DiffRange.Offset),
				Length: int64(diffEntry.DiffRange.Length),
			},
			HammingDistance:          int64(diffEntry.HammingDistance),
			HammingDistanceNon00orFF: int64(diffEntry.HammingDistanceNon00orFF),
		}
		for _, m := range diffEntry.RelatedMeasurements {
			convMeasurement := &diffanalysis.RelatedMeasurement{
				Measurement: &diffanalysis.Measurement{
					ID: m.Description,
				},
			}
			for _, chunk := range m.Measurement.Chunks {
				convMeasurement.Measurement.DataChunks = append(convMeasurement.Measurement.DataChunks, convDataChunk(&chunk))
			}
			for _, chunk := range m.RelatedDataChunks {
				convMeasurement.RelatedDataChunks = append(convMeasurement.RelatedDataChunks, convDataChunk(&chunk))
			}
			convEntry.RelatedMeasurements = append(convEntry.RelatedMeasurements, convMeasurement)
		}
		for _, n := range diffEntry.Nodes {
			convNode := &diffanalysis.NodeInfo{
				UUID:        n.UUID.String(),
				Description: &n.Description,
			}
			convEntry.Nodes = append(convEntry.Nodes, convNode)
		}
		customReport.DiffEntries = append(customReport.DiffEntries, convEntry)
	}

	customReport.Diagnosis = diagnosis
	result.Custom = customReport
	switch diagnosis {
	case diffanalysis.DiffDiagnosis_Match:
	case diffanalysis.DiffDiagnosis_UnsuspiciousDamage:
		result.Issues = append(result.Issues, analysis.Issue{
			Severity:    analysis.SeverityInfo,
			Description: "Not suspicious damage",
		})
	case diffanalysis.DiffDiagnosis_SuspiciousDamage:
		result.Issues = append(result.Issues, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: "Suspicious damage",
		})
	case diffanalysis.DiffDiagnosis_KnownTamperedHost:
		result.Comments = append(result.Comments, "the firmware was tampered by fwcompromised")
	default:
		result.Issues = append(result.Issues, analysis.Issue{
			Severity:    analysis.SeverityWarning,
			Description: fmt.Sprintf("Result diagnosis: '%s'", diagnosis),
		})
	}
	return result, nil
}

func measurementsForDiffAnalysis(log bootengine.Log) diff.Measurements {
	var result diff.Measurements
	for stepIdx, stepResult := range log {
		if stepResult.MeasuredData == nil {
			continue
		}
		for _, m := range stepResult.MeasuredData {
			desc := fmt.Sprintf("step#%d:%s", stepIdx, format.NiceString(stepResult.Step))
			result = append(result, measurementForDiffAnalysis(m, desc))
		}
	}
	return result
}

func measurementForDiffAnalysis(m bootflowtypes.MeasuredData, mDesc string) diff.Measurement {
	result := diff.Measurement{
		Description: mDesc,
		Chunks:      make(diff.DataChunks, 0, len(m.UnionForcedBytesOrReferences)),
		CustomData:  m,
	}
	for idx, chunk := range m.UnionForcedBytesOrReferences {
		cDesc := fmt.Sprintf("%schunk#%d", mDesc, idx)
		if chunk.Reference == nil {
			result.Chunks = append(result.Chunks, diff.DataChunk{
				Description: cDesc,
				ForceBytes:  chunk.ForcedBytes,
				CustomData:  chunk,
			})
			continue
		}
		for idx, r := range chunk.Reference.Ranges {
			rDesc := fmt.Sprintf("%srange#%d", cDesc, idx)
			result.Chunks = append(result.Chunks, diff.DataChunk{
				Description: rDesc,
				Reference:   r,
				CustomData:  chunk,
			})
		}
	}
	return result
}

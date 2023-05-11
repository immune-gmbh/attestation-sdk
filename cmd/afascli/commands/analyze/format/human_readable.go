package format

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/fatih/color"
	"github.com/google/uuid"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/analyzerreport"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/measurements"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/biosrtmvolume/report/generated/biosrtmanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/pspsignature/report/generated/pspsignanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/generated/diffanalysis"
	controllertypes "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/linuxboot/fiano/pkg/amd/apcb"
)

var (
	actualFirmwareBlobTypeID, originalFirmwareBlobTypeID analysis.TypeID
)

func init() {
	actualFirmwareBlobTypeID, _ = analysis.TypeRegistry().TypeIDOf(analysis.ActualFirmwareBlob{})
	originalFirmwareBlobTypeID, _ = analysis.TypeRegistry().TypeIDOf(analysis.OriginalFirmwareBlob{})
}

// HumanReadable writes an Analyze report to the io.Writer in a human readable format.
//
// showNotSupported defines if we should show reports of analyzers, which are
// not applicable. For example to show reports of AMD-related analyzers on an Intel target.
//
// TODO: use original types, instead of converted to Thrift.
func HumanReadable(w io.Writer, result afas.AnalyzeResult_, enableColors bool, showNotSupported bool) {
	jobID, _ := types.NewJobIDFromBytes(result.JobID)
	fmt.Fprintf(w, "Analyze job finished, jobID: %s (0x%X))\n", jobID, result.JobID)
	for idx := 0; idx < len(result.Results); idx++ {
		analyzerResult := result.Results[idx]
		if !showNotSupported {
			if err := analyzerResult.GetAnalyzerOutcome().GetErr(); err != nil && err.ErrorClass == afas.ErrorClass_NotSupported {
				continue
			}
		}
		fmt.Fprintf(w, "=== Results of '%s' ===\n", analyzerResult.AnalyzerName)
		printAnalyzerResult(w, *analyzerResult.AnalyzerOutcome, enableColors)
		fmt.Fprintf(w, "=== End of '%s' ===\n", analyzerResult.AnalyzerName)
	}
	printReferencesToImages(w, result)
}

func printReferencesToImages(w io.Writer, result afas.AnalyzeResult_) {
	var actualImageIDs, originalImageIDs []types.ImageID
	actualImageIDIsSet, originalImageIDIsSet := map[types.ImageID]struct{}{}, map[types.ImageID]struct{}{}
	for idx := 0; idx < len(result.Results); idx++ {
		analyzerResult := result.Results[idx]
		if analyzerResult.ProcessedInputJSON == nil {
			continue
		}

		input := analysis.Input{}
		err := input.UnmarshalJSON([]byte(*analyzerResult.ProcessedInputJSON))
		if err != nil {
			// TODO: print the errors as debug
			continue
		}

		if v, ok := input[actualFirmwareBlobTypeID]; ok {
			if fw, ok := v.(*analysis.ActualFirmwareBlob); ok {
				if actualFirmwareAccessor, ok := fw.Blob.(*controllertypes.AnalyzerFirmwareAccessor); ok {
					imgID := actualFirmwareAccessor.ImageID
					if _, ok := actualImageIDIsSet[imgID]; !ok {
						actualImageIDIsSet[imgID] = struct{}{}
						actualImageIDs = append(actualImageIDs, imgID)
					}
				} else {
					fmt.Fprintf(w, "<unexpected ActualFirmwareBlob.Blob type: %T>\n", fw.Blob)
				}
			} else {
				fmt.Fprintf(w, "<internal error: unexpected ActualFirmwareBlob type: %T>\n", v)
			}
		}

		if v, ok := input[originalFirmwareBlobTypeID]; ok {
			if fw, ok := v.(*analysis.OriginalFirmwareBlob); ok {
				if originalFirmwareAccessor, ok := fw.Blob.(*controllertypes.AnalyzerFirmwareAccessor); ok {
					imgID := originalFirmwareAccessor.ImageID
					if _, ok := originalImageIDIsSet[imgID]; !ok {
						originalImageIDIsSet[imgID] = struct{}{}
						originalImageIDs = append(originalImageIDs, imgID)
					}
				} else {
					fmt.Fprintf(w, "<unexpected OriginalFirmwareBlob.Blob type: %T>\n", fw.Blob)
				}
			} else {
				fmt.Fprintf(w, "<internal error: unexpected OriginalFirmwareBlob type: %T>\n", v)
			}
		}
	}

	// We take only first 16 bytes of the image ID because the probability of an accidental collision
	// on this size is neglectically low. While if the collision is delibirate we will get an explicit
	// error.
	for _, imageID := range actualImageIDs {
		fmt.Fprintf(w, "To download the actual image use:   afascli fetch hex:%s > /tmp/fw-actual.img\n", imageID.String()[:32])
	}
	for _, imageID := range originalImageIDs {
		fmt.Fprintf(w, "To download the original image use: afascli fetch hex:%s > /tmp/fw-orig.img\n", imageID.String()[:32])
	}
}

func fprintfWithColor(w io.Writer, enableColors bool, colorAttr color.Attribute, format string, args ...any) {
	if !enableColors {
		fmt.Fprintf(w, format, args...)
		return
	}
	color.New(colorAttr).Fprintf(w, format, args...)
}

func printAnalyzerResult(w io.Writer, result afas.AnalyzerOutcome, enableColors bool) {
	if result.IsSetErr() {
		err := result.GetErr()
		var colorAttr color.Attribute
		if err.ErrorClass == afas.ErrorClass_NotSupported {
			colorAttr = color.FgGreen
		} else {
			colorAttr = color.FgRed
		}
		fprintfWithColor(w, enableColors, colorAttr, "Got error, class: '%s', description: '%s'\n", err.ErrorClass, err.Description)
	}
	if result.IsSetReport() {
		report := result.GetReport()

		result := "UNKNOWN"
		reportSeverity := maxSeverity(report.Issues)
		switch reportSeverity {
		case analyzerreport.Severity_SeverityInfo:
			result = "OK"
		case analyzerreport.Severity_SeverityWarning:
			result = "WARNING"
		case analyzerreport.Severity_SeverityCritical:
			result = "CRITICAL"
		}
		fprintfWithColor(w, enableColors, severityColor(reportSeverity), "Result: %s\n", result)

		if report.Custom != nil {
			switch {
			case report.Custom.IsSetDiffMeasuredBoot():
				diffMeasuredBoot := report.Custom.GetDiffMeasuredBoot()
				fmt.Fprintf(w, "Diff diagnosis: %s\n", diffMeasuredBoot.GetDiagnosis())
				for _, diffEntry := range diffMeasuredBoot.GetDiffEntries() {
					var offset, length int64
					if diffEntry.Range == nil || (diffEntry.Range.Length == 0 && diffEntry.OBSOLETE_Length != 0) {
						offset, length = diffEntry.OBSOLETE_Start, diffEntry.OBSOLETE_Length
					} else {
						offset, length = diffEntry.Range.Offset, diffEntry.Range.Length
					}
					fmt.Fprintf(w,
						"bitwise hamming distance %7d at 0x%08X--0x%08X; related measurements: %s; nodes: %s:\n",
						diffEntry.HammingDistance,
						offset, offset+length,
						diff.RelatedMeasurementsLaconic(convRelatedMeasurements(diffEntry.RelatedMeasurements)),
						convNodes(diffEntry.Nodes),
					)
					if diffEntry.HammingDistanceNon00orFF*100/diffEntry.HammingDistance < 50 {
						fmt.Fprintf(w, "\tbitwise non 0x00/0xFF hamming distance is %7d\n", diffEntry.HammingDistanceNon00orFF)
					}
				}
			case report.Custom.IsSetIntelACM():
				intelACM := report.Custom.GetIntelACM()
				if intelACM.Original != nil {
					fmt.Fprintf(w, "Original.Date: 0x%08X\n", intelACM.Original.Date)
					fmt.Fprintf(w, "Original.SESVN: %d\n", intelACM.Original.SESVN)
					fmt.Fprintf(w, "Original.TXTSVN: %d\n", intelACM.Original.TXTSVN)
				}
				if intelACM.Received != nil {
					fmt.Fprintf(w, "Actual.Date: 0x%08X\n", intelACM.Received.Date)
					fmt.Fprintf(w, "Actual.SESVN: %d\n", intelACM.Received.SESVN)
					fmt.Fprintf(w, "Actual.TXTSVN: %d\n", intelACM.Received.TXTSVN)
				}
			case report.Custom.IsSetReproducePCR():
				reproducePCR := report.Custom.GetReproducePCR()
				if reproducePCR.ExpectedFlow != measurements.Flow_AUTO { // "AUTO" is also used for "UNDEFINED"
					fmt.Fprintf(w, "Expected flow: %s\n", reproducePCR.ExpectedFlow)
					fmt.Fprintf(w, "Expected locality: %d\n", reproducePCR.ExpectedLocality)
				}
			case report.Custom.IsSetPSPSignature():
				pspSignature := report.Custom.GetPSPSignature()
				for _, item := range pspSignature.GetItems() {
					if item == nil {
						continue
					}
					var colorAttr color.Attribute
					if item.ValidationResult_ == pspsignanalysis.Validation_Correct {
						colorAttr = color.FgGreen
					} else {
						colorAttr = color.FgRed
					}

					var text string
					if item.Entry == nil {
						text = fmt.Sprintf("Directory %s has validation result: %s", item.Directory, item.ValidationResult_)
						fprintfWithColor(w, enableColors, colorAttr, "Directory %s has validation result: %s, description: %s\n", item.Directory, item.ValidationResult_, item.ValidationDescription)
					} else {
						text = fmt.Sprintf("Item %s of directory %s has validation result: %s", *item.Entry, item.Directory, item.ValidationResult_)
					}
					if len(item.ValidationDescription) > 0 {
						text += fmt.Sprintf(" description: '%s'", item.ValidationDescription)
					}
					fprintfWithColor(w, enableColors, colorAttr, text)
				}
			case report.Custom.IsSetBIOSRTMVolume():
				biosRTMVolume := report.Custom.BIOSRTMVolume
				for _, item := range biosRTMVolume.Items {
					if item == nil {
						continue
					}

					fmt.Fprintf(w, "BIOS directory level: %d\n", item.BIOSDirectoryLevel)
					if item.PlatformInfo != nil {
						fmt.Fprintf(w, "PlatformInfo.VendorID: 0x%X\n", item.PlatformInfo.VendorID)
						fmt.Fprintf(w, "PlatformInfo.KeyRevisionID: 0x%X\n", item.PlatformInfo.KeyRevisionID)
						fmt.Fprintf(w, "PlatformInfo.PlatformModelID: 0x%X\n", item.PlatformInfo.PlatformModelID)
					}
					if item.SecurityFeatures != nil {
						fmt.Fprintf(w, "DISABLE_BIOS_KEY_ANTI_ROLLBACK: %t\n", item.SecurityFeatures.DisableBIOSKeyAntiRollback)
						fmt.Fprintf(w, "DISABLE_AMD_BIOS_KEY_USE: %t\n", item.SecurityFeatures.DisableAMDBIOSKeyUse)
						fmt.Fprintf(w, "DISABLE_SECURE_DEBUG_UNLOCK: %t\n", item.SecurityFeatures.DisableSecureDebugUnlock)
					}

					var colorAttr color.Attribute
					if item.ValidationResult_ == biosrtmanalysis.Validation_CorrectSignature {
						colorAttr = color.FgGreen
					} else {
						colorAttr = color.FgRed
					}
					fprintfWithColor(w, enableColors, colorAttr, "Validation result: %s\n", item.ValidationResult_)
					if len(item.ValidationDescription) > 0 {
						fprintfWithColor(w, enableColors, colorAttr, "Validation description: %s", item.ValidationDescription)
					}
				}
			case report.Custom.IsSetAPCBSecurityTokens():
				apcbSecurityTokens := report.Custom.APCBSecurityTokens
				for _, biosDir := range apcbSecurityTokens.DirectoryTokens {
					fmt.Fprintf(w, "=== BIOS Directory level %d tokens: ===\n", biosDir.BIOSDirectoryLevel)
					for _, token := range biosDir.Tokens {
						fmt.Fprintf(w, "Token.ID: %s\n", token.ID)
						fmt.Fprintf(w, "Token.PriorityMask: %s\n", apcb.PriorityMask(token.PriorityMask))
						fmt.Fprintf(w, "Token.BoardMask: 0x%X\n", uint16(token.BoardMask))
						switch {
						case token.Value.IsSetBoolean():
							fmt.Fprintf(w, "Token.Value [boolean]: %t\n", *token.Value.Boolean)
						case token.Value.IsSetByte():
							fmt.Fprintf(w, "Token.Value [byte]: 0x%X\n", *token.Value.Byte)
						case token.Value.IsSetWord():
							fmt.Fprintf(w, "Token.Value [word]: 0x%X\n", *token.Value.Word)
						case token.Value.IsSetDWord():
							fmt.Fprintf(w, "Token.Value [dword]: 0x%X\n", *token.Value.DWord)
						}
						fmt.Fprintf(w, "Token.Value: %s\n", token.Value)
					}
				}
			default:
				fmt.Fprintln(w, "Not supported report.Custom type")
				if resultJSON, err := json.MarshalIndent(report.Custom, "", " "); err == nil {
					fmt.Fprintf(w, "%s\n", resultJSON)
				}
			}
		}
		comments := report.GetComments()
		if len(comments) > 0 {
			fmt.Fprintln(w, "Comments:")
			for _, comment := range comments {
				fmt.Fprintf(w, "%s\n", comment)
			}
		}

		issues := report.GetIssues()
		if len(issues) > 0 {
			fmt.Fprintln(w, "Issues:")
			for _, issue := range issues {
				if issue == nil {
					continue
				}
				fprintfWithColor(w, enableColors, severityColor(issue.Severity), "\tSeverity: %s\n", issue.Severity)
				if issue.Description != nil {
					fmt.Fprintf(w, "\tDescription: %s\n", *issue.Description)
				}
				if issue.Custom != nil {
					// TODO: add printing of custom issue information here
					// else
					{
						fmt.Fprintln(w, "\tNot supported issue.Custom type")
						if resultJSON, err := json.MarshalIndent(issue.Custom, "", " "); err == nil {
							fmt.Fprintf(w, "\t%s\n", resultJSON)
						}
					}
				}
			}
		}
	}
}

// TODO: create a package `typeconv` for these conversions to Thrift and back.
func convNodes(nodes []*diffanalysis.NodeInfo) []diff.NodeInfo {
	result := make([]diff.NodeInfo, 0, len(nodes))
	for _, node := range nodes {
		uuid, err := uuid.Parse(node.UUID)
		if err != nil {
			// TODO: return a warning
			_ = err
		}
		result = append(result, diff.NodeInfo{
			UUID:        uuid,
			Description: node.GetDescription(),
		})
	}
	return result
}

// TODO: create a package `typeconv` for these conversions to Thrift and back.
func measurementIDFromString(idString string) pcr.MeasurementID {
	idString = strings.ToUpper(idString)
	for id := pcr.MeasurementIDUndefined; id < pcr.EndOfMeasurementID; id++ {
		if strings.ToUpper(id.String()) == idString {
			return id
		}
	}
	return pcr.MeasurementIDUndefined
}

// TODO: create a package `typeconv` for these conversions to Thrift and back.
func dataChunkIDFromString(idString string) pcr.DataChunkID {
	idString = strings.ToUpper(idString)
	for id := pcr.DataChunkIDUndefined; id < pcr.EndOfDataChunkID; id++ {
		if strings.ToUpper(id.String()) == idString {
			return id
		}
	}
	return pcr.DataChunkIDUndefined
}

// TODO: create a package `typeconv` for these conversions to Thrift and back.
func convDataChunks(dataChunks []*diffanalysis.DataChunk) diff.DataChunks {
	result := make(diff.DataChunks, 0, len(dataChunks))
	for _, dataChunk := range dataChunks {
		convDataChunk := diff.DataChunk{
			Description: dataChunk.ID,
			CustomData:  dataChunk,
		}
		switch {
		case dataChunk.Data.IsSetRange():
			r := dataChunk.Data.GetRange()
			convDataChunk.Reference = pkgbytes.Range{
				Offset: uint64(r.Offset),
				Length: uint64(r.Length),
			}
		case dataChunk.Data.IsSetForceData():
			convDataChunk.ForceBytes = dataChunk.Data.ForceData
		default:
			// TODO: return this as a warning
		}
		result = append(result, convDataChunk)
	}

	return result
}

// TODO: create a package `typeconv` for these conversions to Thrift and back.
func convRelatedMeasurements(ms []*diffanalysis.RelatedMeasurement) []diff.RelatedMeasurement {
	result := make([]diff.RelatedMeasurement, 0, len(ms))
	for _, m := range ms {
		convMeasurement := diff.RelatedMeasurement{
			Measurement: diff.Measurement{
				Description: m.Measurement.ID,
				Chunks:      convDataChunks(m.Measurement.DataChunks),
				CustomData:  m,
			},
			RelatedDataChunks: convDataChunks(m.RelatedDataChunks),
		}
		result = append(result, convMeasurement)
	}

	return result
}

func severityColor(severity analyzerreport.Severity) color.Attribute {
	switch severity {
	case analyzerreport.Severity_SeverityInfo:
		return color.FgGreen
	case analyzerreport.Severity_SeverityWarning:
		return color.FgYellow
	case analyzerreport.Severity_SeverityCritical:
		return color.FgRed
	}
	return color.FgRed
}

func maxSeverity(issues []*analyzerreport.Issue) analyzerreport.Severity {
	result := analyzerreport.Severity_SeverityInfo
	for _, issue := range issues {
		if issue == nil {
			continue
		}
		if result < issue.Severity {
			result = issue.Severity
		}
	}

	return result
}

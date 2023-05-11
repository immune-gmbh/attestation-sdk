package biosrtmvolume

import (
	"context"
	"errors"
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/amd/biosrtmvolume/report/biosrtmanalysis"
	"github.com/linuxboot/fiano/pkg/amd/psb"

	"github.com/facebookincubator/go-belt/tool/logger"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

func init() {
	analysis.RegisterType((*biosrtmanalysis.CustomReport)(nil))
}

const (
	metaPlatformsVendorID = 0x8D
)

// ID represents the unique id of BIOSRTMVolumeSignature analyzer that checks BIOS
const ID analysis.AnalyzerID = biosrtmanalysis.BIOSRTMVolumeAnalyzerID

// Input is an input structure required for analyzer
type Input struct {
	Firmware analysis.ActualPSPFirmware
}

// NewExecutorInput builds an analysis.Executor's input required for BIOSRTMVolume analyzer
func NewExecutorInput(
	actualFirmware analysis.Blob,
) (analysis.Input, error) {
	if actualFirmware == nil {
		return nil, fmt.Errorf("firmware image should be specified")
	}

	result := analysis.NewInput()
	result.AddActualFirmware(
		actualFirmware,
	)
	return result, nil
}

// Analyzer that verifies AMD's BIOS RTM Volume
type Analyzer struct{}

// New returns a new object of PSPSignature analyzer
func New() analysis.Analyzer[Input] {
	return &Analyzer{}
}

// ID implements the ID method required for analysis.Analyzer
func (analyzer *Analyzer) ID() analysis.AnalyzerID {
	return ID
}

// Analyze makes the ACM gathering
func (analyzer *Analyzer) Analyze(ctx context.Context, in Input) (*analysis.Report, error) {
	log := logger.FromCtx(ctx)
	pspFirmware := in.Firmware.AMDFirmware().PSPFirmware()

	var customInfo biosrtmanalysis.CustomReport
	if pspFirmware.BIOSDirectoryLevel1 != nil {
		rtmVolume, err := analyzer.checkBIOSRTMVolume(ctx, in.Firmware.AMDFirmware(), 1)
		if err != nil {
			log.Errorf("Check of RTM volume of BIOS directory level 1 failed: %v", err)
			return nil, err
		}
		customInfo.Items = append(customInfo.Items, rtmVolume)
	}
	if pspFirmware.BIOSDirectoryLevel2 != nil {
		rtmVolume, err := analyzer.checkBIOSRTMVolume(ctx, in.Firmware.AMDFirmware(), 2)
		if err != nil {
			log.Errorf("Check of RTM volume of BIOS directory level 1 failed: %v", err)
			return nil, err
		}
		customInfo.Items = append(customInfo.Items, rtmVolume)
	}

	var result analysis.Report
	result.Custom = customInfo
	for _, rtmVolume := range customInfo.Items {
		result.Issues = append(result.Issues, getRTMVolumeIssues(*rtmVolume)...)
	}
	return &result, nil
}

func (analyzer *Analyzer) checkBIOSRTMVolume(
	ctx context.Context,
	amdFw *amd_manifest.AMDFirmware,
	level uint,
) (*biosrtmanalysis.BIOSRTMVolume, error) {
	result := biosrtmanalysis.BIOSRTMVolume{
		BIOSDirectoryLevel: int8(level),
	}

	res, err := psb.ValidateRTM(amdFw, level)
	if err != nil {
		result.ValidationResult_ = analyzer.processError(err, level)
		result.ValidationDescription = err.Error()
	} else {
		if res.Error() != nil {
			result.ValidationResult_ = analyzer.processError(res.Error(), level)
			result.ValidationDescription = res.String()
		} else {
			result.ValidationResult_ = biosrtmanalysis.Validation_CorrectSignature
		}
	}

	if signingKey, err := psb.GetPSBSignBIOSKey(amdFw, level); err == nil {
		platformBinding, err := psb.GetPlatformBindingInfo(signingKey)
		if err != nil {
			logger.FromCtx(ctx).Errorf("Failed to get platform binding info: ", err)
			return nil, err
		}
		result.PlatformInfo = &biosrtmanalysis.PlatformBindingInfo{
			VendorID:        int16(platformBinding.VendorID),
			KeyRevisionID:   int8(platformBinding.KeyRevisionID),
			PlatformModelID: int8(platformBinding.PlatformModelID),
		}

		securityFeatures, err := psb.GetSecurityFeatureVector(signingKey)
		if err != nil {
			logger.FromCtx(ctx).Errorf("Failed to get security features: ", err)
			return nil, err
		}
		result.SecurityFeatures = &biosrtmanalysis.SecurityFeatureVector{
			DisableBIOSKeyAntiRollback: securityFeatures.DisableBIOSKeyAntiRollback,
			DisableAMDBIOSKeyUse:       securityFeatures.DisableAMDBIOSKeyUse,
			DisableSecureDebugUnlock:   securityFeatures.DisableSecureDebugUnlock,
		}
	}
	return &result, nil
}

func (analyzer *Analyzer) processError(inErr error, level uint) biosrtmanalysis.Validation {
	var errNotFound psb.ErrNotFound
	if errors.As(inErr, &errNotFound) {
		if biosItem, ok := errNotFound.GetItem().(psb.BIOSDirectoryEntryItem); ok {
			switch biosItem.Entry {
			case amd_manifest.BIOSRTMVolumeEntry:
				return biosrtmanalysis.Validation_RTMVolumeNotFound
			case psb.BIOSRTMSignatureEntry:
				return biosrtmanalysis.Validation_RTMSignatureNotFound
			case psb.OEMSigningKeyEntry:
				return biosrtmanalysis.Validation_PSBDisabled
			}
		}
		return biosrtmanalysis.Validation_Unknown
	}

	var errInvalidFormat psb.ErrInvalidFormat
	if errors.As(inErr, &errInvalidFormat) {
		return biosrtmanalysis.Validation_InvalidFormat
	}

	var (
		signatureCheckErr *psb.SignatureCheckError
		unknownKeyErr     *psb.UnknownSigningKeyError
	)
	if errors.As(inErr, &signatureCheckErr) || errors.As(inErr, &unknownKeyErr) {
		return biosrtmanalysis.Validation_IncorrectSignature
	}
	return biosrtmanalysis.Validation_Unknown
}

func getRTMVolumeIssues(rtmVolume biosrtmanalysis.BIOSRTMVolume) []analysis.Issue {
	var result []analysis.Issue
	switch rtmVolume.ValidationResult_ {
	case biosrtmanalysis.Validation_Unknown:
		result = append(result, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: fmt.Sprintf("Unknown problem: %s", rtmVolume.ValidationDescription),
		},
		)
	case biosrtmanalysis.Validation_CorrectSignature:
		// no issues
	case biosrtmanalysis.Validation_RTMVolumeNotFound:
		result = append(result, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: "RTM Volume was not found",
		},
		)
	case biosrtmanalysis.Validation_RTMSignatureNotFound:
		result = append(result, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: "RTM Signature was not found",
		},
		)
	case biosrtmanalysis.Validation_PSBDisabled:
		// not an issue
	case biosrtmanalysis.Validation_InvalidFormat:
		result = append(result, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: fmt.Sprintf("Invalid format: '%s'", rtmVolume.ValidationDescription),
		},
		)
	case biosrtmanalysis.Validation_IncorrectSignature:
		result = append(result, analysis.Issue{
			Severity:    analysis.SeverityCritical,
			Description: fmt.Sprintf("Incorrect signature: '%s'", rtmVolume.ValidationDescription),
		},
		)
	default:
		result = append(result, analysis.Issue{
			Severity: analysis.SeverityCritical,
			Description: fmt.Sprintf("Unsupported validation result (please fix AFAS): '%s', description: '%s'",
				rtmVolume.ValidationResult_, rtmVolume.ValidationDescription,
			),
		},
		)
	}

	if rtmVolume.PlatformInfo != nil {
		platformInfo := rtmVolume.PlatformInfo
		if platformInfo.VendorID != metaPlatformsVendorID {
			result = append(result, analysis.Issue{
				Severity: analysis.SeverityCritical,
				Description: fmt.Sprintf("Not a Meta defined VendorID: '0x%X', expexted: '0x%X'",
					platformInfo.VendorID, metaPlatformsVendorID,
				),
			},
			)
		}
	}
	if rtmVolume.SecurityFeatures != nil {
		securityFeatures := rtmVolume.SecurityFeatures
		if securityFeatures.DisableAMDBIOSKeyUse {
			result = append(result, analysis.Issue{
				Severity:    analysis.SeverityCritical,
				Description: "DISABLE_AMD_BIOS_KEY_USE expected 0 but actual 1",
			},
			)
		}
		if securityFeatures.DisableBIOSKeyAntiRollback {
			result = append(result, analysis.Issue{
				Severity:    analysis.SeverityCritical,
				Description: "DISABLE_BIOS_KEY_ANTI_ROLLBACK expected 0 but actual 1",
			},
			)
		}
		if securityFeatures.DisableSecureDebugUnlock {
			result = append(result, analysis.Issue{
				Severity:    analysis.SeverityCritical,
				Description: "DISABLE_SECURE_DEBUG_UNLOCK expected 0 but actual 1",
			},
			)
		}
	}
	return result
}

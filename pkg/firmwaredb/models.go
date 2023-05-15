package rtpdb

import (
	"privatecore/firmware/analyzer/pkg/rtpdb/models"
)

// FirmwareType represents description of firmware type values
type FirmwareType = models.FirmwareType

const (
	// UndefinedFirmwareType is a default value
	UndefinedFirmwareType models.FirmwareType = 0

	// BiosFirmwareType represents BIOS
	BiosFirmwareType = models.BiosFirmwareType

	// BMCFirmwareType represents BMC
	BMCFirmwareType = models.BMCFirmwareType

	// FlashFirmwareType represents FLASH
	FlashFirmwareType = models.FlashFirmwareType

	// RaidFirmwareType represents RAID
	RaidFirmwareType = models.RaidFirmwareType

	// NICFirmwareType represents NIC
	NICFirmwareType = models.NICFirmwareType

	// LinuxBootFirmwareType represents LinuxBoot
	LinuxBootFirmwareType = models.LinuxBootFirmwareType

	// OpenBMCFirmwareType represents OpenBMC
	OpenBMCFirmwareType = models.OpenBMCFirmwareType
)

// EvaluationStatus represents description of evaluation status type values
type EvaluationStatus = models.EvaluationStatus

const (
	// EvaluationStatusMassProduction represents Mass Production
	EvaluationStatusMassProduction = models.EvaluationStatusMassProduction

	// EvaluationStatusEvaluation represents Evaluation
	EvaluationStatusEvaluation = models.EvaluationStatusEvaluation

	// EvaluationStatusEVT represents EVT
	EvaluationStatusEVT = models.EvaluationStatusEVT

	// EvaluationStatusDVT represents DVT
	EvaluationStatusDVT = models.EvaluationStatusDVT

	// EvaluationStatusPVT represents PVT
	EvaluationStatusPVT = models.EvaluationStatusPVT

	// EvaluationStatusIT represents IT
	EvaluationStatusIT = models.EvaluationStatusIT

	// EvaluationStatusMPTesting represents MP_TESTING
	EvaluationStatusMPTesting = models.EvaluationStatusMPTesting

	// EvaluationStatusEdge represents EDGE
	EvaluationStatusEdge = models.EvaluationStatusEdge

	// EvaluationStatusMPPilot represents MP_PILOT
	EvaluationStatusMPPilot = models.EvaluationStatusMPPilot

	// EvaluationStatusSneakPeek represents SNEAK_PEEK
	EvaluationStatusSneakPeek = models.EvaluationStatusSneakPeek

	// EvaluationStatusLab represents LAB
	EvaluationStatusLab = models.EvaluationStatusLab
)

// QualificationStatus represents description of qualification status type values
type QualificationStatus = models.QualificationStatus

const (
	// QualificationStatusUntested represents UNTESTED qualification status
	QualificationStatusUntested = models.QualificationStatusUntested

	// QualificationStatusHavocTesting represents HAVOC_TESTING qualification status
	QualificationStatusHavocTesting = models.QualificationStatusHavocTesting

	// QualificationStatusCSPTesting represents CSP_TESTING qualification status
	QualificationStatusCSPTesting = models.QualificationStatusCSPTesting

	// QualificationStatusProduction represents PRODUCTION qualification status
	QualificationStatusProduction = models.QualificationStatusProduction

	// QualificationStatusBad represents BAD qualification status
	QualificationStatusBad = models.QualificationStatusBad

	// QualificationStatusUnscanned represents UNSCANNED qualification status
	QualificationStatusUnscanned = models.QualificationStatusUnscanned

	// QualificationStatusUnpackaged represents UNPACKAGED qualification status
	QualificationStatusUnpackaged = models.QualificationStatusUnpackaged

	// QualificationStatusNeedsReview represents NEEDS_REVIEW qualification status
	QualificationStatusNeedsReview = models.QualificationStatusNeedsReview
)

// Firmware represent a row of table containing metadata
// about firmware images.
//
// Some fields are obsolete, some fields has wrong type and so on -- these
// problems are on the table schema side.
type Firmware = models.Firmware

// ModelFamily represent a row of table containing connections
// between model family and model IDs (model == asset model).
type ModelFamily = models.ModelFamily

// ModelFamilies is a set of rows (of ModelFamilyTableName).
type ModelFamilies = models.ModelFamilies

// Date is a parsed date value
type Date = models.Date

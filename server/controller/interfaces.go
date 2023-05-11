package controller

import (
	"context"
	"io"

	// external
	// TODO: remove this abstraction leak from here:
	"github.com/jmoiron/sqlx"

	// meta
	"facebook/core_systems/server/device"
	"libfb/go/rfe"
	"rfe/RockfortExpress"

	// internal
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/rtp"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpdb"
	rtpdb_models "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpdb/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpfw"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

type storageInterface interface {
	io.Closer

	// Image
	Insert(ctx context.Context, imageMeta models.ImageMetadata, imageData []byte) error
	UpsertReproducedPCRs(ctx context.Context, reproducedPCRs models.ReproducedPCRs) error
	Get(ctx context.Context, imageID types.ImageID) ([]byte, *models.ImageMetadata, error)
	GetBytes(ctx context.Context, imageID types.ImageID) (firmwareImage []byte, err error)
	Find(ctx context.Context, filters storage.FindFilter) (imageMetas []*models.ImageMetadata, unlockFn context.CancelFunc, err error)
	FindOne(ctx context.Context, filters storage.FindFilter) (*models.ImageMetadata, context.CancelFunc, error)

	// AnalyzeReport
	InsertAnalyzeReport(ctx context.Context, report *models.AnalyzeReport) error
	FindAnalyzeReports(ctx context.Context, filterInput storage.AnalyzeReportFindFilter, tx *sqlx.Tx, limit uint) ([]*models.AnalyzeReport, error)
}

type scubaInterface interface {
	io.Closer

	Log(v interface{}) error
}

type serfInterface interface {
	io.Closer

	GetDeviceByName(hostname string) (*device.Device, error)
	GetDeviceById(assetID int64) (*device.Device, error)
}

type rfeInterface interface {
	SQL(table string, query string, opts ...rfe.QueryOpt) (*RockfortExpress.SQLQueryResult_, error)
}

type rtpDBReader struct {
	db *rtpdb.DB
}

func (t *rtpDBReader) GetFirmwares(ctx context.Context, filters ...rtpdb.Filter) ([]rtpdb_models.Firmware, error) {
	return rtpdb.GetFirmwares(ctx, t.db, filters...)
}

func (t *rtpDBReader) GetModelFamilyByModel(ctx context.Context, modelID uint64) (*rtpdb_models.ModelFamily, error) {
	return rtpdb.GetModelFamilyByModel(ctx, t.db, modelID)
}

func (t *rtpDBReader) Close() error {
	return t.db.Close()
}

func newRTPDBReader(db *rtpdb.DB) *rtpDBReader {
	return &rtpDBReader{db: db}
}

type rtpDBInterface interface {
	GetFirmwares(ctx context.Context, filters ...rtpdb.Filter) ([]rtpdb_models.Firmware, error)
	GetModelFamilyByModel(ctx context.Context, modelID uint64) (*rtpdb_models.ModelFamily, error)
	io.Closer
}

type rtpfwInterface interface {
	Update(ctx context.Context) (bool, error)
	GetFirmware(
		ctx context.Context,
		firmwareVersion, firmwareDateString string,
		modelFamilyID *uint64,
		evaluationStatus rtp.EvaluationStatus,
		cachingPolicy types.CachingPolicy,
	) (rtpfw.Firmware, error)
	UpsertPCRs(
		ctx context.Context,
		controlPCR []byte,
		firmwareVersion, firmwareDateString string,
		modelFamilyID *uint64,
		evaluationStatus rtp.EvaluationStatus,
		pcrs rtpfw.PCRValues,
		updateTags bool,
		forcedTags ...types.MeasurementTag,
	) error
}

type analysisDataCalculatorInterface = analysis.DataCalculatorInterface

type originalFirmwareStorage interface {
	DownloadByFilename(ctx context.Context, filename string) ([]byte, string, error)
	DownloadByEverstoreHandle(ctx context.Context, handle string) ([]byte, string, error)
}

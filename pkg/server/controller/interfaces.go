package controller

import (
	"context"
	"io"

	"github.com/jmoiron/sqlx"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/device"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarestorage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarestorage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

type FirmwareStorage interface {
	io.Closer

	// Image
	Insert(ctx context.Context, imageMeta models.ImageMetadata, imageData []byte) error
	UpsertReproducedPCRs(ctx context.Context, reproducedPCRs models.ReproducedPCRs) error
	Get(ctx context.Context, imageID types.ImageID) ([]byte, *models.ImageMetadata, error)
	GetBytes(ctx context.Context, imageID types.ImageID) (firmwareImage []byte, err error)
	Find(ctx context.Context, filters firmwarestorage.FindFilter) (imageMetas []*models.ImageMetadata, unlockFn context.CancelFunc, err error)
	FindOne(ctx context.Context, filters firmwarestorage.FindFilter) (*models.ImageMetadata, context.CancelFunc, error)

	// AnalyzeReport
	InsertAnalyzeReport(ctx context.Context, report *models.AnalyzeReport) error
	FindAnalyzeReports(ctx context.Context, filterInput firmwarestorage.AnalyzeReportFindFilter, tx *sqlx.Tx, limit uint) ([]*models.AnalyzeReport, error)
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
}

type DeviceGetter interface {
	GetDeviceByHostname(hostname string) (*device.Device, error)
	GetDeviceByAssetID(assetID int64) (*device.Device, error)
}

type analysisDataCalculatorInterface = analysis.DataCalculatorInterface

type originalFWImageRepository interface {
	DownloadByVersion(ctx context.Context, version string) ([]byte, string, error)
}

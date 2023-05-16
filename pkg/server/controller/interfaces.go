package controller

import (
	"context"
	"io"

	"github.com/jmoiron/sqlx"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/device"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

type Storage interface {
	io.Closer

	// Image
	Insert(ctx context.Context, imageMeta models.FirmwareImageMetadata, imageData []byte) error
	UpsertReproducedPCRs(ctx context.Context, reproducedPCRs models.ReproducedPCRs) error
	Get(ctx context.Context, imageID types.ImageID) ([]byte, *models.FirmwareImageMetadata, error)
	GetBytes(ctx context.Context, imageID types.ImageID) (firmwareImage []byte, err error)
	Find(ctx context.Context, filters storage.FindFirmwareFilter) (imageMetas []*models.FirmwareImageMetadata, unlockFn context.CancelFunc, err error)
	FindOne(ctx context.Context, filters storage.FindFirmwareFilter) (*models.FirmwareImageMetadata, context.CancelFunc, error)

	// AnalyzeReport
	InsertAnalyzeReport(ctx context.Context, report *models.AnalyzeReport) error
	FindAnalyzeReports(ctx context.Context, filterInput storage.AnalyzeReportFindFilter, tx *sqlx.Tx, limit uint) ([]*models.AnalyzeReport, error)
}

type DeviceGetter interface {
	GetDeviceByHostname(hostname string) (*device.Device, error)
	GetDeviceByAssetID(assetID int64) (*device.Device, error)
}

type analysisDataCalculatorInterface = analysis.DataCalculatorInterface

type originalFWImageRepository interface {
	DownloadByVersion(ctx context.Context, version string) ([]byte, string, error)
}

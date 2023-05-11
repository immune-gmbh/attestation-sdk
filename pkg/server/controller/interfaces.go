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
	InsertFirmware(ctx context.Context, imageMeta models.FirmwareImageMetadata, imageData []byte) error
	GetFirmware(ctx context.Context, imageID types.ImageID) ([]byte, *models.FirmwareImageMetadata, error)
	GetFirmwareBytes(ctx context.Context, imageID types.ImageID) (firmwareImage []byte, err error)
	FindFirmware(ctx context.Context, filters storage.FindFirmwareFilter) (imageMetas []*models.FirmwareImageMetadata, unlockFn context.CancelFunc, err error)
	FindFirmwareOne(ctx context.Context, filters storage.FindFirmwareFilter) (*models.FirmwareImageMetadata, context.CancelFunc, error)

	// ReproducedPCRs
	UpsertReproducedPCRs(ctx context.Context, reproducedPCRs models.ReproducedPCRs) error

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

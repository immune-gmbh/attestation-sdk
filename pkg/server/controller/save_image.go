package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/pkg/field"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/uuid"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
)

func (ctrl *Controller) saveImage(
	ctx context.Context,
	meta models.ImageMetadata,
	firmwareImage []byte,
) (*types.ImageID, error) {
	if len(firmwareImage) == 0 {
		return nil, fmt.Errorf("len(firmwareImage) == 0")
	}
	return ctrl.newSaveImageJob(meta, firmwareImage).Execute(ctx)
}

func (ctrl *Controller) saveImageAsync(
	ctx context.Context,
	meta models.ImageMetadata,
	firmwareImage []byte,
) {
	ctrl.launchAsync(ctx, func(ctx context.Context) {
		log := logger.FromCtx(ctx)
		id, err := ctrl.saveImage(ctx, meta, firmwareImage)
		if err == nil {
			log.Debugf("Saved image with ID 0x%X", *id)
			return
		}
		if errors.As(err, &storage.ErrAlreadyExists{}) {
			log.Debugf("Image %#+v already exists", meta)
		} else {
			log.Errorf("Failed to save image %#+v: %v", meta, err)
		}
	})
}

type saveImageJob struct {
	*Controller
	JobID           uuid.UUID
	CreatedAt       time.Time
	FirmwareMeta    models.ImageMetadata
	FirmwareContent []byte

	ctx context.Context
}

func (ctrl *Controller) newSaveImageJob(
	meta models.ImageMetadata,
	firmwareImage []byte,
) *saveImageJob {
	job := &saveImageJob{
		JobID:      uuid.New(),
		Controller: ctrl,
		CreatedAt:  time.Now(),

		FirmwareMeta:    meta,
		FirmwareContent: firmwareImage,
	}
	return job
}

func (job *saveImageJob) Execute(ctx context.Context) (*types.ImageID, error) {
	ctx = beltctx.WithFields(
		ctx,
		field.Map[string]{
			"jobID":   job.JobID.String(),
			"jobType": "saveImage",
		},
	)
	span, ctx := tracer.StartChildSpanFromCtx(ctx, "")
	defer span.Finish()

	job.ctx = ctx
	job.FirmwareMeta.CalcMissingInfo(ctx, job.FirmwareContent)
	job.FirmwareMeta.TSAdd = time.Now()

	if err := job.FirmwareStorage.Insert(ctx, job.FirmwareMeta, job.FirmwareContent); err != nil {
		return nil, fmt.Errorf("unable to save image '%s': %w", job.FirmwareMeta.ImageID, err)
	}

	return &job.FirmwareMeta.ImageID, nil
}

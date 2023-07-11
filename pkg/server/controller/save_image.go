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
	"errors"
	"fmt"
	"time"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/pkg/field"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/uuid"

	"github.com/immune-gmbh/attestation-sdk/pkg/storage"
	"github.com/immune-gmbh/attestation-sdk/pkg/storage/models"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"
)

func (ctrl *Controller) saveImage(
	ctx context.Context,
	meta models.FirmwareImageMetadata,
	firmwareImage []byte,
) (*types.ImageID, error) {
	if len(firmwareImage) == 0 {
		return nil, fmt.Errorf("len(firmwareImage) == 0")
	}
	return ctrl.newSaveImageJob(meta, firmwareImage).Execute(ctx)
}

func (ctrl *Controller) saveImageAsync(
	ctx context.Context,
	meta models.FirmwareImageMetadata,
	firmwareImage []byte,
) {
	ctrl.launchAsync(ctx, func(ctx context.Context) {
		log := logger.FromCtx(ctx)
		id, err := ctrl.saveImage(ctx, meta, firmwareImage)
		if err == nil {
			log.Debugf("Saved image with ID %s", *id)
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
	FirmwareMeta    models.FirmwareImageMetadata
	FirmwareContent []byte

	ctx context.Context
}

func (ctrl *Controller) newSaveImageJob(
	meta models.FirmwareImageMetadata,
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

	if err := job.FirmwareStorage.InsertFirmware(ctx, job.FirmwareMeta, job.FirmwareContent); err != nil {
		return nil, fmt.Errorf("unable to save image '%s': %w", job.FirmwareMeta.ImageID, err)
	}

	return &job.FirmwareMeta.ImageID, nil
}

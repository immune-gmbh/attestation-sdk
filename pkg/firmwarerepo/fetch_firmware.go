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

package firmwarerepo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
)

// DownloadByVersion downloads a raw firmware file by its name
func (storage *FirmwareRepo) DownloadByVersion(ctx context.Context, filename string) ([]byte, string, error) {
	return storage.FetchFirmwareByURL(ctx, storage.baseURL+filename)
}

type image struct {
	Bytes    []byte
	Filename string
}

type fetchFirmwareJob struct {
	Image           image
	Error           error
	ctx             context.Context
	firmwareStorage *FirmwareRepo
	url             string
	doneChan        chan struct{}
}

// FetchFirmwareByURL returns a firmware image by URL.
func (fwRepo *FirmwareRepo) FetchFirmwareByURL(
	ctx context.Context,
	url string,
) (imageBytes []byte, filename string, err error) {
	job := fwRepo.fetchFirmware(ctx, url)
	<-job.Done()
	logger.FromCtx(ctx).Debugf("fetch-firmware received results: len:%d, name:%s, err:%v", len(job.Image.Bytes), job.Image.Filename, job.Error)
	return job.Image.Bytes, job.Image.Filename, job.Error
}

func (fwRepo *FirmwareRepo) fetchFirmware(ctx context.Context, url string) *fetchFirmwareJob {

	// The high-level logic of this code:
	//
	// * We want to avoid downloading the same image multiple times in parallel
	//   so if there are multiple FetchFirmware requests with the same url,
	//   then they all waits for one real HTTP request to complete. So
	//   for each URL we create a job and re-use it if necessary.

	span, ctx := tracer.StartChildSpanFromCtx(ctx, "FirmwareStorageSubJob.fetchFirmware")
	defer span.Finish()
	log := logger.FromCtx(ctx)

	fwRepo.fetchFirmwareJobsMutex.Lock()
	defer fwRepo.fetchFirmwareJobsMutex.Unlock()

	job := fwRepo.fetchFirmwareJobs[url]
	if job != nil {
		return job
	}

	log.Debugf("creating a new firmware-fetch for '%s'", url)
	job = fwRepo.newFetchFirmwareJob(ctx, url, func(image image) {
		log.Debugf("finished downloading the image for '%s'", url)

		fwRepo.fetchFirmwareJobsMutex.Lock()
		fwRepo.fetchFirmwareJobs[url] = nil
		fwRepo.fetchFirmwareJobsMutex.Unlock()
	})
	fwRepo.fetchFirmwareJobs[url] = job
	return job
}

func (fwRepo *FirmwareRepo) newFetchFirmwareJob(
	ctx context.Context,
	url string,
	onSuccess func(image),
) (job *fetchFirmwareJob) {

	ctx = beltctx.WithField(
		ctx, "pkg", "firmwarestorage",
	)

	job = &fetchFirmwareJob{
		ctx:             beltctx.WithField(ctx, "fetchFirmwareJob", url),
		url:             url,
		firmwareStorage: fwRepo,
		doneChan:        make(chan struct{}),
	}
	go func() {
		defer func() {
			logger.FromCtx(ctx).Debugf("download '%s' result: len:%d, name:%s, err:%v", url, len(job.Image.Bytes), job.Image.Filename, job.Error)
			close(job.doneChan)
		}()

		job.fetch()
		if job.Error != nil {
			return
		}

		onSuccess(job.Image)
	}()
	return
}

func (job *fetchFirmwareJob) fetch() {
	data, filename, err := job.fetchFromURL()

	if err != nil {
		job.Error = err
		return
	}

	job.Image = image{Bytes: data, Filename: filename}
}

func (job *fetchFirmwareJob) fetchFromURL() ([]byte, string, error) {
	parsedURL, err := url.Parse(job.url)
	if err != nil {
		return nil, "", ErrParseURL{Err: err, URL: job.url}
	}

	var (
		imageBytes []byte
		filename   string
	)

	switch parsedURL.Scheme {
	case "http", "https":
		pathParts := strings.Split(parsedURL.Path, "/")
		filename = pathParts[len(pathParts)-1]
		imageBytes, err = job.httpFetch()
	default:
		return nil, "", fmt.Errorf("unknown scheme: '%s'", parsedURL.Scheme)
	}
	return imageBytes, filename, err
}

func (job *fetchFirmwareJob) httpFetch() ([]byte, error) {
	log := logger.FromCtx(job.ctx)
	log.Debugf("downloading a file from '%s'", job.url)
	req, err := http.NewRequestWithContext(job.ctx, http.MethodGet, job.url, nil)
	if err != nil {
		err = ErrHTTPMakeRequest{Err: err, URL: job.url}
		logger.FromCtx(job.ctx).Errorf("internal error: %v", err)
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, ErrHTTPGet{Err: err, URL: job.url}
	}
	defer resp.Body.Close()
	log.Debugf("status code: %d", resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode > 300 {
		log.Warnf("invalid response status code: %d", resp.StatusCode)
		return nil, ErrHTTPGet{Err: fmt.Errorf("invalid status code: %d", resp.StatusCode), URL: job.url}
	}

	imageBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrHTTPGetBody{Err: err, URL: job.url}
	}

	return imageBytes, nil
}

func (job *fetchFirmwareJob) Done() <-chan struct{} {
	return job.doneChan
}

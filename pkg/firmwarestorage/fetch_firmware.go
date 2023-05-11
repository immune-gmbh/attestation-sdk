package firmwarestorage

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"facebook/storage/everstore"
	"libfb/go/sr"
	"libfb/go/thriftbase"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/tracer"
	"github.com/facebookincubator/go-belt/tool/logger"
)

const (
	everstoreURLPrefix               = "everstore://"
	firmwareTarballRepositoryBaseURL = `https://yum/opsfiles_bin/bin/firmware/`
)

// DownloadByFilename downloads a raw firmware file by its name
func (storage *FirmwareStorage) DownloadByFilename(ctx context.Context, filename string) ([]byte, string, error) {
	return storage.FetchFirmwareByURL(ctx, firmwareTarballRepositoryBaseURL+filename)
}

// DownloadByEverstoreHandle downloads a raw firmware file by its handle
func (storage *FirmwareStorage) DownloadByEverstoreHandle(ctx context.Context, handle string) ([]byte, string, error) {
	return storage.FetchFirmwareByURL(ctx, everstoreURLPrefix+handle)
}

type image struct {
	Bytes    []byte
	Filename string
}

type fetchFirmwareJob struct {
	Image           image
	Error           error
	ctx             context.Context
	firmwareStorage *FirmwareStorage
	url             string
	doneChan        chan struct{}
}

// FetchFirmwareByURL returns a firmware image by URL.
func (storage *FirmwareStorage) FetchFirmwareByURL(
	ctx context.Context,
	url string,
) (imageBytes []byte, filename string, err error) {
	job := storage.fetchFirmware(ctx, url)
	<-job.Done()
	logger.FromCtx(ctx).Debugf("fetch-firmware received results: len:%d, name:%s, err:%v", len(job.Image.Bytes), job.Image.Filename, job.Error)
	return job.Image.Bytes, job.Image.Filename, job.Error
}

func (storage *FirmwareStorage) fetchFirmware(ctx context.Context, url string) *fetchFirmwareJob {

	// The high-level logic of this code:
	//
	// * We want to avoid downloading the same image multiple times in parallel
	//   so if there are multiple FetchFirmware requests with the same url,
	//   then they all waits for one real HTTP request to complete. So
	//   for each URL we create a job and re-use it if necessary.

	span, ctx := tracer.StartChildSpanFromCtx(ctx, "FirmwareStorageSubJob.fetchFirmware")
	defer span.Finish()
	log := logger.FromCtx(ctx)

	storage.fetchFirmwareJobsMutex.Lock()
	defer storage.fetchFirmwareJobsMutex.Unlock()

	job := storage.fetchFirmwareJobs[url]
	if job != nil {
		return job
	}

	log.Debugf("creating a new firmware-fetch for '%s'", url)
	job = storage.newFetchFirmwareJob(ctx, url, func(image image) {
		log.Debugf("finished downloading the image for '%s'", url)

		storage.fetchFirmwareJobsMutex.Lock()
		storage.fetchFirmwareJobs[url] = nil
		storage.fetchFirmwareJobsMutex.Unlock()
	})
	storage.fetchFirmwareJobs[url] = job
	return job
}

func (storage *FirmwareStorage) newFetchFirmwareJob(
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
		firmwareStorage: storage,
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
	var (
		data     []byte
		filename string
		err      error
	)
	switch {
	case strings.HasPrefix(job.url, everstoreURLPrefix):
		data, filename, err = job.fetchFromEverstore()
	default:
		data, filename, err = job.fetchFromURL()
	}

	if err != nil {
		job.Error = err
		return
	}

	job.Image = image{Bytes: data, Filename: filename}
}

func (job *fetchFirmwareJob) fetchFromEverstore() ([]byte, string, error) {
	handle := job.url[len(everstoreURLPrefix):]
	logger.FromCtx(job.ctx).Infof("everstore handle: '%s'", handle)

	conn, err := sr.GetClient("dfsrouter.common", sr.Timeout(time.Minute), sr.ThriftOptions([]thriftbase.Option{thriftbase.Timeout(time.Minute)}))
	if err != nil {
		return nil, handle, fmt.Errorf("failed to get everstore connection: %w", err)
	}
	everstoreClient := everstore.NewEverstoreClient(conn.Transport(), conn, conn)
	data, err := everstoreClient.Read(handle, job.firmwareStorage.callerName)
	return data, handle, err
}

func (job *fetchFirmwareJob) fetchFromURL() ([]byte, string, error) {
	parsedURL, err := url.Parse(job.url)
	if err != nil {
		return nil, "", ErrParseURL{Err: err, URL: job.url}
	}
	pathParts := strings.Split(parsedURL.Path, "/")
	filename := pathParts[len(pathParts)-1]

	imageBytes, err := job.httpFetch()
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

	imageBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrHTTPGetBody{Err: err, URL: job.url}
	}

	return imageBytes, nil
}

func (job *fetchFirmwareJob) Done() <-chan struct{} {
	return job.doneChan
}

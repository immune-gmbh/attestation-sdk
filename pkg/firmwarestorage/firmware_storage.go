package firmwarestorage

import (
	"sync"
)

const (
	// cacheCompressedImages defines how many images should we cache on our side
	// to prevent downloading them from the repository each time.
	cacheCompressedImages = 8

	// cacheCompressedImageSizeLimit defines maximal size of an
	// compressed image which could be saved into the cache
	cacheCompressedImageSizeLimit = 32 << 20
)

// FirmwareStorage is responsible for providing an original image of a specified
// firmware version. Currently it is implemented through ugly logic of
// downloading a tarball and looking for image from it.
//
// TODO: reimplement this logic to download images from Everstore/Manifold.
type FirmwareStorage struct {
	baseURL    string
	callerName string

	firmwareUncompressedCount int64
	fetchFirmwareJobsMutex    sync.Mutex
	fetchFirmwareJobs         map[string]*fetchFirmwareJob
}

// NewFirmwareStorage returns an instance of FirmwareStorage.
func NewFirmwareStorage(
	baseURL string,
	callerName string,
) *FirmwareStorage {
	return &FirmwareStorage{
		baseURL:           baseURL,
		fetchFirmwareJobs: map[string]*fetchFirmwareJob{},
		callerName:        callerName,
	}
}

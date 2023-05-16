package firmwarerepo

import (
	"sync"
)

// FirmwareRepo is responsible for providing an original image of a specified
// firmware version. Currently it is implemented through ugly logic of
// downloading a tarball and looking for image from it.
//
// TODO: reimplement this logic to download images from Everstore/BlobStorage.
type FirmwareRepo struct {
	baseURL    string
	callerName string

	fetchFirmwareJobsMutex sync.Mutex
	fetchFirmwareJobs      map[string]*fetchFirmwareJob
}

// New returns an instance of FirmwareRepo.
func New(
	baseURL string,
	callerName string,
) *FirmwareRepo {
	return &FirmwareRepo{
		baseURL:           baseURL,
		fetchFirmwareJobs: map[string]*fetchFirmwareJob{},
		callerName:        callerName,
	}
}

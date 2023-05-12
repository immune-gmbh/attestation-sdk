package objectstorage

import (
	"context"
	"fmt"
	"net/url"
)

type ObjectStorage interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Store(ctx, key string, blob []byte) error
}

func New(urlString string) (ObjectStorage, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse url '%s': %w", urlString, err)
	}
	switch parsedURL.Scheme {
	case "fs":
		return newFS(parsedURL.Host + parsedURL.RawPath)
	default:
		return nil, fmt.Errorf("unknown scheme '%s'", parsedURL.Scheme)
	}
}

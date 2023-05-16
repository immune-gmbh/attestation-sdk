package blobstorage

import (
	"context"
	"fmt"
	"io"
	"net/url"
)

type BlobStorage interface {
	io.Closer

	Get(ctx context.Context, key []byte) ([]byte, error)
	Replace(ctx context.Context, key []byte, blob []byte) error
	Delete(ctx context.Context, key []byte) error
}

func New(urlString string) (BlobStorage, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse URL '%s': %w", urlString, err)
	}
	switch parsedURL.Scheme {
	case "fs":
		rootDir := parsedURL.Path
		return newFS(rootDir)
	default:
		return nil, fmt.Errorf("unknown scheme '%s'", parsedURL.Scheme)
	}
}

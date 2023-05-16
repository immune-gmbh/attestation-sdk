package blobstorage

import (
	"context"
	"encoding/base32"
	"os"
	"path/filepath"
)

// FS is a dummy implementation of ObjectStorage.
type FS struct {
	RootDir string
}

var _ BlobStorage = (*FS)(nil)

func newFS(rootDir string) (*FS, error) {
	return &FS{
		RootDir: rootDir,
	}, nil
}

func (fs *FS) Get(ctx context.Context, key []byte) ([]byte, error) {
	objPath := fs.getPath(key)
	return os.ReadFile(objPath)
}

func (fs *FS) Replace(ctx context.Context, key []byte, blob []byte) error {
	objPath := fs.getPath(key)
	return os.WriteFile(objPath, blob, 0640)
}

func (fs *FS) Delete(ctx context.Context, key []byte) error {
	objPath := fs.getPath(key)
	return os.Remove(objPath)
}

func (fs *FS) getPath(key []byte) string {
	return filepath.Join(fs.RootDir, base32.StdEncoding.EncodeToString(key))
}

func (fs *FS) Close() error {
	// TODO: forbid use-after-close
	return nil
}

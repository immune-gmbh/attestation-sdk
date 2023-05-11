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

package blobstorage

import (
	"context"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
)

// FS is a dummy implementation of ObjectStorage.
type FS struct {
	RootDir string
}

var _ BlobStorage = (*FS)(nil)

func newFS(rootDir string) (*FS, error) {
	err := os.MkdirAll(rootDir, 0750)
	if err != nil {
		return nil, fmt.Errorf("unable to create the rootdir '%s': %w", rootDir, err)
	}
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

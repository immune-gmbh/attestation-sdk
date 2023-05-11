package storage

import (
	"context"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
)

type dummyCache struct{}

var _ Cache = (*dummyCache)(nil)

func (dummyCache) Get(ctx context.Context, objectKey objhash.ObjHash) any {
	return nil
}

func (dummyCache) Set(ctx context.Context, objectKey objhash.ObjHash, object any, objectSize uint64) {
}

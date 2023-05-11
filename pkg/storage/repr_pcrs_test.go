package storage

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"libfb/go/ephemdb"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"

	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/facebookincubator/go-belt/tool/logger"
	xlogrus "github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	prodXDBTier = "xdb.afas"
)

func TestInsertAndFindReproducedPCRs(t *testing.T) {
	ctx := logger.CtxWithLogger(
		context.Background(),
		xlogrus.Default().WithLevel(logger.LevelDebug),
	)

	dbtier, close := createEphemeral(t)
	defer close()

	stor, err := NewStorage(dbtier, &mockManifold{}, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, stor)

	stableHash := make(types.HashValue, 128)
	stableHash[0] = 1
	stableHash[1] = 2
	stableHash[127] = 3

	initial, err := models.NewReproducedPCRs(stableHash, nil, tpmdetection.TypeTPM20, make([]byte, sha1.Size), make([]byte, sha256.Size))
	require.NoError(t, err)

	require.NoError(t, stor.UpsertReproducedPCRs(ctx, initial))

	key, err := models.NewUniqueKey(stableHash, nil, tpmdetection.TypeTPM20)
	require.NoError(t, err)
	found, err := stor.FindOneReproducedPCRs(ctx, key)
	require.NoError(t, err)

	insertedID := found.ID
	initial.ID = insertedID
	require.Equal(t, initial, found)

	newPCR0SHA1 := make([]byte, sha1.Size)
	newPCR0SHA1[1] = 0x10
	newPCR0SHA256 := make([]byte, sha256.Size)
	newPCR0SHA256[1] = 0x10
	next, err := models.NewReproducedPCRs(stableHash, nil, tpmdetection.TypeTPM20, newPCR0SHA1, newPCR0SHA256)
	require.NoError(t, err)
	require.NoError(t, stor.UpsertReproducedPCRs(ctx, next))

	found, err = stor.FindOneReproducedPCRs(ctx, key)
	require.NoError(t, err)
	next.ID = insertedID
	require.Equal(t, next, found)

	results, err := stor.SelectReproducedPCRs(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, next, results[0])
}

func createEphemeral(t *testing.T) (string, func()) {
	ephemeralDB, err := ephemdb.NewEphemDBFactory("baremetal_security", ephemdb.SourceShard(prodXDBTier))
	require.NoError(t, err)

	newShard, nonce, err := ephemeralDB.Allocate(ephemdb.FiveMinutes)
	require.NoError(t, err)
	require.NotEmpty(t, newShard)
	require.NotEqual(t, prodXDBTier, newShard)
	return newShard, func() {
		assert.NoError(t, ephemeralDB.Deallocate(newShard, nonce))
	}
}

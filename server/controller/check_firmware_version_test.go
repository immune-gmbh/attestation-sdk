package controller

import (
	"context"
	"fmt"
	"testing"

	"libfb/go/ephemdb"
	"libfb/go/fbmysql"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpdb"

	"github.com/stretchr/testify/require"
)

func TestCheckFirmwareVersion(t *testing.T) {
	rtpDB, releaseShard, err := createEphemeralShardConnection()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rtpDB.Close())
		require.NoError(t, releaseShard())
	}()

	dataRows := []string{
		`379003422589862,_binary 'added tarball filename','',0,'','',1521183600,_binary 'a:2:{i:0;a:2:{s:4:\"hash\";s:40:\"347AC63C09BC38CACC6C660D3DBBA02B46EDA57A\";s:4:\"tags\";a:3:{i:0;i:242117919604953;i:1;i:582975628748684;i:2;i:343914949450946;}}i:1;a:2:{s:4:\"hash\";s:40:\"DA10392C05589F48E17B012F641CC81D65E818E2\";s:4:\"tags\";a:3:{i:0;i:307293539682079;i:1;i:582975628748684;i:2;i:343914949450946;}}}',1,_binary 'F06_3B17',290801018053272,3,'',100001980685071,1529091020,92,'',0,'',_binary 'a:0:{}',_binary 'F06_3B17.tar.gz','',1,0,'','',''`,
	}
	for _, insertedItem := range dataRows {
		result, err := rtpDB.ExecContext(context.Background(), fmt.Sprintf("INSERT INTO `firmware` VALUES (%s)", insertedItem))
		require.NoError(t, err)
		cnt, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), cnt)
	}

	controller := makeController(t)
	controller.rtpDB = newRTPDBReader(rtpDB)
	defer func() {
		require.NoError(t, controller.Close())
	}()

	result, err := controller.CheckFirmwareVersion(context.Background(), []afas.FirmwareVersion{
		{
			Version: "F06_3B17",
			Date:    "03/16/2018",
		},
		{
			Version: "F06_3B17",
			Date:    "11/11/2011",
		},
		{
			Version: "F0E_3A15",
			Date:    "BLAH-BLAH",
		},
	})
	require.NoError(t, err)
	require.Equal(t, []bool{true, false, false}, result)
}

func createEphemeralShardConnection() (*rtpdb.DB, func() error, error) {
	ephemeralDB, err := ephemdb.NewEphemDBFactory("baremetal_security", ephemdb.SourceShard(rtpdb.DefaultXDBTier))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create an ephermal DB factory: %w", err)
	}

	var succeeded bool
	newShard, nonce, err := ephemeralDB.Allocate(ephemdb.FiveMinutes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to allocate shard: %w", err)
	}
	defer func() {
		if succeeded {
			return
		}
		ephemeralDB.Deallocate(newShard, nonce)
	}()

	if len(newShard) == 0 {
		return nil, nil, fmt.Errorf("allocated shard name is empty")
	}
	if newShard == rtpdb.DefaultXDBTier {
		return nil, nil, fmt.Errorf("allocated shard name equal prod db tier")
	}

	testDB, err := rtpdb.GetDB(fbmysql.DefaultConfigRW(newShard))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to allocate shard: %w", err)
	}
	succeeded = true
	return testDB, func() error {
		return ephemeralDB.Deallocate(newShard, nonce)
	}, nil
}

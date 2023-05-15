package rtpdb

import (
	"context"
	"fmt"
	"testing"

	"libfb/go/ephemdb"
	"libfb/go/fbmysql"
	"privatecore/firmware/analyzer/if/rtp"
	"privatecore/firmware/analyzer/pkg/rtpdb/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDateStringConvertion(t *testing.T) {
	tests := []struct {
		FWDate       string
		FirmwareDate uint64
		Expected     string
	}{
		{
			FWDate:       "08/16/2017",
			FirmwareDate: 1502866800,
			Expected:     "08/16/2017",
		},
		{
			FWDate:       "",
			FirmwareDate: 1502866800,
			Expected:     "08/16/2017",
		},
		{
			FWDate:       "",
			FirmwareDate: 1550736000,
			Expected:     "02/21/2019",
		},
		{
			FWDate:       "",
			FirmwareDate: 1556866800,
			Expected:     "05/03/2019",
		},
		{
			FWDate:       "",
			FirmwareDate: 1504681200,
			Expected:     "09/06/2017",
		},
	}

	for _, test := range tests {
		f := Firmware{
			FWDate:       test.FWDate,
			FirmwareDate: test.FirmwareDate,
		}
		require.Equal(t, test.Expected, f.GetDate().String())
	}
}

func TestFirmwareReadTableAccess(t *testing.T) {
	testDB, close := createEphemeralShardConnection(t)
	defer close()

	// Modified copy-pasted from production table dump
	{
		insertedFirmwareRows := []string{
			`134157967328517,'','',0,'',_binary '01/01/2010',1262304000,_binary 'a:2:{i:0;a:2:{s:4:\"hash\";s:40:\"DBB30B985F1C20509EC48C7D469C315404B17C28\";s:4:\"tags\";a:1:{i:0;i:307293539682079;}}i:1;a:2:{s:4:\"hash\";s:40:\"097E00E3B8D9A8EA07CEB53092060AAC2D1660F5\";s:4:\"tags\";a:1:{i:0;i:242117919604953;}}}',1,_binary 'F20_3A15',325246221231721,3,_binary '2017Q4',100001980685071,1507055018,92,'',0,'',_binary 'a:0:{}',_binary 'monolake_bios_F20_3A15.tar.gz','',0,1,'','',''`,
			`134157967328518,'','',0,'',_binary '01/01/2017',0,_binary 'a:2:{i:0;a:2:{s:4:\"hash\";s:40:\"DBB30B985F1C20509EC48C7D469C315404B17C28\";s:4:\"tags\";a:1:{i:0;i:307293539682079;}}i:1;a:2:{s:4:\"hash\";s:40:\"097E00E3B8D9A8EA07CEB53092060AAC2D1660F5\";s:4:\"tags\";a:1:{i:0;i:242117919604953;}}}',1,_binary 'F20_3A15',325246221231721,3,_binary '2017Q4',100001980685071,1507055018,92,'',0,'',_binary 'a:0:{}',_binary 'monolake_bios_F20_3A15.tar.gz','',1,1,'','',''`,
			`134157967328519,'','',0,'','',1502866800,_binary 'a:2:{i:0;a:2:{s:4:\"hash\";s:40:\"DBB30B985F1C20509EC48C7D469C315404B17C28\";s:4:\"tags\";a:1:{i:0;i:307293539682079;}}i:1;a:2:{s:4:\"hash\";s:40:\"097E00E3B8D9A8EA07CEB53092060AAC2D1660F5\";s:4:\"tags\";a:1:{i:0;i:242117919604953;}}}',1,_binary 'F20_3A15',325246221231721,3,_binary '2017Q4',100001980685071,1507055018,92,'',0,'',_binary 'a:0:{}',_binary 'monolake_bios_F20_3A15.tar.gz','',0,1,'','',''`,
			`134157967328520,'','',0,'',_binary '01/01/2000',0,_binary 'a:2:{i:0;a:2:{s:4:\"hash\";s:40:\"DBB30B985F1C20509EC48C7D469C315404B17C28\";s:4:\"tags\";a:1:{i:0;i:307293539682079;}}i:1;a:2:{s:4:\"hash\";s:40:\"097E00E3B8D9A8EA07CEB53092060AAC2D1660F5\";s:4:\"tags\";a:1:{i:0;i:242117919604953;}}}',1,_binary 'F20_3A15',325246221231722,3,_binary '2017Q4',100001980685071,1507055018,92,'',0,'',_binary 'a:0:{}',_binary 'monolake_bios_F20_3A15.tar.gz','',0,1,'','',''`,
			`379003422589862,_binary 'added tarball filename','',0,'','',1521183600,_binary 'a:2:{i:0;a:2:{s:4:\"hash\";s:40:\"347AC63C09BC38CACC6C660D3DBBA02B46EDA57A\";s:4:\"tags\";a:3:{i:0;i:242117919604953;i:1;i:582975628748684;i:2;i:343914949450946;}}i:1;a:2:{s:4:\"hash\";s:40:\"DA10392C05589F48E17B012F641CC81D65E818E2\";s:4:\"tags\";a:3:{i:0;i:307293539682079;i:1;i:582975628748684;i:2;i:343914949450946;}}}',1,_binary 'F06_3B17',290801018053272,3,'',100001980685071,1529091020,92,'',0,'',_binary 'a:0:{}',_binary 'F06_3B17.tar.gz','',1,0,'','',''`,
			// make dummy item with RaidFirmwareType
			`12345,'','',0,'','',1502866800,_binary 'a:2:{i:0;a:2:{s:4:\"hash\";s:40:\"DBB30B985F1C20509EC48C7D469C315404B17C28\";s:4:\"tags\";a:1:{i:0;i:307293539682079;}}i:1;a:2:{s:4:\"hash\";s:40:\"097E00E3B8D9A8EA07CEB53092060AAC2D1660F5\";s:4:\"tags\";a:1:{i:0;i:242117919604953;}}}',4,_binary 'FAKE20_3A15',325246221231721,3,_binary '2017Q4',100001980685071,1507055018,92,'',0,'',_binary 'a:0:{}',_binary 'monolake_bios_F20_3A15.tar.gz','',0,1,'','',''`,
		}
		insertRawFirmwareRows(t, testDB, insertedFirmwareRows...)

		insertedModelFamilyRows := []string{
			`325246221231722,'MONOLAKE_T1 (Quanta)','a:2:{i:0;i:56441;i:1;i:333581;}',122995491648590`,
		}
		insertRawModelFamilyRows(t, testDB, insertedModelFamilyRows...)
	}

	expectedFirmware := Firmware{
		EvaluationStatus:    EvaluationStatusMassProduction,
		FWDate:              "",
		FirmwareDate:        1502866800,
		FWHash:              `a:2:{i:0;a:2:{s:4:"hash";s:40:"DBB30B985F1C20509EC48C7D469C315404B17C28";s:4:"tags";a:1:{i:0;i:307293539682079;}}i:1;a:2:{s:4:"hash";s:40:"097E00E3B8D9A8EA07CEB53092060AAC2D1660F5";s:4:"tags";a:1:{i:0;i:242117919604953;}}}`,
		ModelFamilyID:       &[]uint64{325246221231721}[0],
		QualificationStatus: QualificationStatusProduction,
		TargetYearQuarter:   "2017Q4",
		UploadByID:          100001980685071,
		UploadByDate:        1507055018,
		VendorID:            0x5c,
		Misc:                "a:0:{}",
		Filename:            "monolake_bios_F20_3A15.tar.gz",
		IsLatestFirmware:    false,
		IsShipping:          true,
		MPN:                 &[]string{""}[0],
		ComponentPath:       &[]string{""}[0],
	}

	t.Run("select_firmware", func(t *testing.T) {
		selectedFirmwares, err := GetFirmwaresByVersionAndDate(context.Background(), testDB, "F20_3A15", "08/16/2017")
		require.NoError(t, err)

		expectedFirmware := expectedFirmware
		expectedFirmware.ID = 134157967328519
		expectedFirmware.FirmwareType = rtp.FirmwareType_BIOS
		expectedFirmware.FWVersion = "F20_3A15"
		require.Equal(t, []Firmware{expectedFirmware}, selectedFirmwares)

		resultFirmware, err := GetFirmwareByID(context.Background(), testDB, 134157967328519)
		require.NoError(t, err)
		require.Equal(t, expectedFirmware, resultFirmware)

		_, err = GetFirmwareByID(context.Background(), testDB, 11111)
		require.Error(t, err)
	})

	t.Run("get_latest_firmware_by_version", func(t *testing.T) {
		selectedFirmware, err := GetLatestFirmwareByVersion(context.Background(), testDB, "F20_3A15")
		require.NoError(t, err)

		expectedFirmware := expectedFirmware
		expectedFirmware.ID = 134157967328518
		expectedFirmware.FirmwareType = rtp.FirmwareType_BIOS
		expectedFirmware.FWVersion = "F20_3A15"
		expectedFirmware.FWDate = "01/01/2017"
		expectedFirmware.FirmwareDate = 0
		expectedFirmware.IsLatestFirmware = true
		require.Equal(t, expectedFirmware, selectedFirmware)
	})

	t.Run("get_firmware_by_model", func(t *testing.T) {
		selectedFirmware, err := GetFirmwareByModel(context.Background(), testDB, 56441)
		require.NoError(t, err)
		require.NotNil(t, selectedFirmware)
		require.Equal(t, &[]uint64{325246221231722}[0], selectedFirmware.ModelFamilyID)
	})

	t.Run("get_firmware_by_type", func(t *testing.T) {
		selectedFirmwares, err := GetFirmwaresByType(context.Background(), testDB, RaidFirmwareType)
		require.NoError(t, err)

		expectedFirmware := expectedFirmware
		expectedFirmware.ID = 12345
		expectedFirmware.FirmwareType = rtp.FirmwareType_RAID
		expectedFirmware.FWVersion = "FAKE20_3A15"
		require.Equal(t, []Firmware{expectedFirmware}, selectedFirmwares)
	})

	t.Run("filters", func(t *testing.T) {
		startDate, err := models.ParseDate("01/01/2015")
		require.NoError(t, err)
		endDate, err := models.ParseDate("08/16/2017")
		require.NoError(t, err)

		selectedFirmwares, err := GetFirmwares(
			context.Background(), testDB,
			FilterVersion("F20_3A15"),
			FilterDate{Start: startDate, End: endDate},
			FilterEvaluationStatus(EvaluationStatusMassProduction),
			FilterQualificationStatuses([]rtp.QualificationStatus{QualificationStatusProduction}),
			FilterTypes([]rtp.FirmwareType{rtp.FirmwareType_BIOS}),
			FilterNot{FilterQualificationStatuses([]rtp.QualificationStatus{QualificationStatusCSPTesting, QualificationStatusHavocTesting})},
		)

		require.NoError(t, err)

		expectedFirmware0 := expectedFirmware
		expectedFirmware0.ID = 134157967328518
		expectedFirmware0.FirmwareType = rtp.FirmwareType_BIOS
		expectedFirmware0.FWVersion = "F20_3A15"
		expectedFirmware0.FWDate = "01/01/2017"
		expectedFirmware0.FirmwareDate = 0
		expectedFirmware0.IsLatestFirmware = true
		expectedFirmware1 := expectedFirmware
		expectedFirmware1.ID = 134157967328519
		expectedFirmware1.FirmwareType = rtp.FirmwareType_BIOS
		expectedFirmware1.FWVersion = "F20_3A15"
		require.Equal(t, []Firmware{expectedFirmware0, expectedFirmware1}, selectedFirmwares)
	})
}

func TestFirmwareAtomicUpdate(t *testing.T) {
	testDB, close := createEphemeralShardConnection(t)
	defer close()

	insertedRows := []string{
		`134157967328519,'','',0,'',_binary '08/16/2017',1502866800,_binary 'INITIAL',1,_binary 'F20_3A15',325246221231721,3,_binary '2017Q4',100001980685071,1507055018,92,'',0,'',_binary 'a:0:{}',_binary 'monolake_bios_F20_3A15.tar.gz','',1,1,'','',''`,
	}
	insertRawFirmwareRows(t, testDB, insertedRows...)

	updated, err := AtomicUpdateFirmwareHash(context.Background(), testDB, 134157967328519, "UPDATED", "NOT_INITIAL")
	require.NoError(t, err)
	require.False(t, updated)

	updated, err = AtomicUpdateFirmwareHash(context.Background(), testDB, 11111, "UPDATED", "INITIAL")
	require.NoError(t, err)
	require.False(t, updated)

	selectedFirmwares, err := GetFirmwaresByVersionAndDate(context.Background(), testDB, "F20_3A15", "08/16/2017")
	require.NoError(t, err)
	require.Len(t, selectedFirmwares, 1)
	require.Equal(t, models.FWHashSerialized("INITIAL"), selectedFirmwares[0].FWHash)

	updated, err = AtomicUpdateFirmwareHash(context.Background(), testDB, 134157967328519, "UPDATED", "INITIAL")
	require.NoError(t, err)
	require.True(t, updated)

	selectedFirmwares, err = GetFirmwaresByVersionAndDate(context.Background(), testDB, "F20_3A15", "08/16/2017")
	require.NoError(t, err)
	require.Len(t, selectedFirmwares, 1)
	require.Equal(t, models.FWHashSerialized("UPDATED"), selectedFirmwares[0].FWHash)
}

func createEphemeralShardConnection(t *testing.T) (*DB, func()) {
	ephemeralDB, err := ephemdb.NewEphemDBFactory("baremetal_security", ephemdb.SourceShard(DefaultXDBTier))
	require.NoError(t, err)

	var succeeded bool

	newShard, nonce, err := ephemeralDB.Allocate(ephemdb.FiveMinutes)
	require.NoError(t, err)
	require.NotEmpty(t, newShard)
	require.NotEqual(t, DefaultXDBTier, newShard)
	defer func() {
		if succeeded {
			return
		}
		assert.NoError(t, ephemeralDB.Deallocate(newShard, nonce))
	}()

	testDB, err := GetDB(fbmysql.DefaultConfigRW(newShard))
	require.NoError(t, err)
	defer func() {
		if succeeded {
			return
		}
		assert.NoError(t, testDB.Close())
	}()
	succeeded = true
	return testDB, func() {
		assert.NoError(t, ephemeralDB.Deallocate(newShard, nonce))
		assert.NoError(t, testDB.Close())
	}
}

func insertRawModelFamilyRows(t *testing.T, testDB *DB, rawRows ...string) {
	for _, insertedItem := range rawRows {
		result, err := testDB.ExecContext(context.Background(), fmt.Sprintf("INSERT INTO `model_family` VALUES (%s)", insertedItem))
		require.NoError(t, err)
		cnt, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), cnt)
	}
}

func insertRawFirmwareRows(t *testing.T, testDB *DB, rawRows ...string) {
	for _, insertedItem := range rawRows {
		result, err := testDB.ExecContext(context.Background(), fmt.Sprintf("INSERT INTO `firmware` VALUES (%s)", insertedItem))
		require.NoError(t, err)
		cnt, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), cnt)
	}
}

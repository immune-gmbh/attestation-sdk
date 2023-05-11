package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"reflect"
	"sort"
	"testing"
	"time"

	"facebook/core_systems/server/device"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/rtp"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarestorage"
	gatingMocks "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/gating/mocks"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/measurements"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpdb"
	rtpdb_models "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpdb/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpfw"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/scubareport"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"privatecore/firmware/samples"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestReportHostConfiguration(t *testing.T) {
	// gating setup
	gate := "ramdisk_attestation_report_config"
	fakeGateChecker := gatingMocks.NewFakeGateChecker()
	fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

	rtpfwMock := newRTPFWMock()
	hostConfigScubaReporter := &scubaMock{}
	controller, err := newInternal(
		context.Background(),
		0,
		&storageMock{},
		newSERFMock(),
		&firmwareStorageMock{},
		&rfeMock{},
		rtpfwMock,
		&dummyRTPDB{
			getModelFamilyByModel: func(ctx context.Context, modelID uint64) (*rtpdb_models.ModelFamily, error) {
				if modelID == 123 {
					return &rtpdb_models.ModelFamily{ID: 1}, nil
				}
				return nil, fmt.Errorf("unexpected modelID: %d", modelID)
			},
		},
		&analysisDataCalculatorMock{},
		fakeGateChecker,
		&scubaMock{},
		"dummy_scuba1",
		hostConfigScubaReporter,
		time.Hour,
		time.Hour,
		10,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, controller)
	defer func() {
		assert.NoError(t, controller.Close())
	}()

	firmwareImage, err := samples.GetFile("firmwares", "F20_3A15.bin.xz")
	require.NoError(t, err)

	f203A15 := rtpfw.Firmware{
		Metadata: rtpfw.FirmwareMeta{
			PCRValues: types.PCRValues{
				{
					Value: mustHexDecode("097E00E3B8D9A8EA07CEB53092060AAC2D1660F5"),
					Properties: types.Properties{
						types.PropertyIntelTXT(false),
					},
				},
				{
					Value: mustHexDecode("DBB30B985F1C20509EC48C7D469C315404B17C28"),
					Properties: types.Properties{
						types.PropertyIntelTXT(true),
					},
				},
			},
		},
		ImageFile: rtpfw.ImageFile{
			Name: "F20_3A15.bin",
			Data: firmwareImage,
		},
	}
	rtpfwMock.add("F20_3A15", "16/08/2017", &[]uint64{1}[0], f203A15)

	t.Run("firmware_not_found", func(t *testing.T) {
		rtpfwMock.upsertPCRs = func(ctx context.Context, controlPCR []byte, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, pcrs rtpfw.PCRValues, updateTags bool, forcedTags ...types.MeasurementTag) error {
			require.Fail(t, "insert PCR0 should not be called")
			return nil
		}
		resultPCR0, err := controller.ReportHostConfiguration(
			context.Background(),
			&afas.HostInfo{
				ModelID: &[]int32{123}[0],
			},
			"UNKNOWN_FW",
			"16/08/2017",
			tpmdetection.TypeTPM20,
			nil, nil, nil,
		)
		require.ErrorAs(t, err, &ErrFetchOrigFirmware{})
		require.Empty(t, resultPCR0.PCR0SHA1)
		require.Empty(t, resultPCR0.PCR0SHA256)

		require.Len(t, hostConfigScubaReporter.loggedItems, 1)
	})

	t.Run("txt_enabled", func(t *testing.T) {
		hostConfigScubaReporter.loggedItems = nil

		var insertPCRsCalledCount int
		var insertedPCRs [][]byte
		var insertedFirmwareVersion string
		var insertedFirmwareDateString string
		rtpfwMock.upsertPCRs = func(ctx context.Context, controlPCR []byte, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, pcrs rtpfw.PCRValues, updateTags bool, forcedTags ...types.MeasurementTag) error {
			insertPCRsCalledCount++
			insertedFirmwareVersion = firmwareVersion
			insertedFirmwareDateString = firmwareDateString
			for _, pcr := range pcrs {
				insertedPCRs = append(insertedPCRs, pcr.Value)
			}
			require.Equal(t, types.MeasurementTags{types.PCRValidated}, types.MeasurementTags(forcedTags))
			return nil
		}
		sort.Slice(insertedPCRs, func(i, j int) bool {
			return len(insertedPCRs[i]) < len(insertedPCRs[j])
		})

		hostname := "some-host.prn.facebook.com"
		assetID := int64(1)
		modelID := int32(123)
		hostInfo := &afas.HostInfo{
			Hostname: &hostname,
			AssetID:  &assetID,
			ModelID:  &modelID,
		}

		resultPCRs, err := controller.ReportHostConfiguration(context.Background(), hostInfo, "F20_3A15", "16/08/2017", tpmdetection.TypeTPM20, nil, nil, nil)
		require.NoError(t, err)
		require.Equal(t, mustHexDecode("3254E2292F39292550249CECC9FE94ABA735893C"), resultPCRs.PCR0SHA1)
		require.Equal(t, mustHexDecode("A1CBF20205D161859E7D62452813E290F155905461ED3954C73664041D8E323D"), resultPCRs.PCR0SHA256)

		require.Equal(t, 1, insertPCRsCalledCount)
		require.Equal(t, "F20_3A15", insertedFirmwareVersion)
		require.Equal(t, "16/08/2017", insertedFirmwareDateString)
		require.Equal(t,
			[][]byte{mustHexDecode("3254E2292F39292550249CECC9FE94ABA735893C"), mustHexDecode("A1CBF20205D161859E7D62452813E290F155905461ED3954C73664041D8E323D")},
			insertedPCRs,
		)

		expectedScubaItem := scubareport.NewHostConfiguration(
			int32(assetID), hostname, modelID,
			"F20_3A15", "16/08/2017", nil,
			tpmdetection.TypeTPM20, nil, nil, resultPCRs.PCR0SHA1, resultPCRs.PCR0SHA256,
		)
		require.Equal(t, []interface{}{expectedScubaItem}, hostConfigScubaReporter.loggedItems)
	})
}

func TestReportHostConfigurationInvalidFirmwaeImage(t *testing.T) {
	gate := "ramdisk_attestation_report_config"
	fakeGateChecker := gatingMocks.NewFakeGateChecker()
	fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

	rtpfwMock := newRTPFWMock()
	hostConfigScubaReporter := &scubaMock{}
	controller, err := newInternal(
		context.Background(),
		0,
		&storageMock{},
		newSERFMock(),
		&firmwareStorageMock{},
		&rfeMock{},
		rtpfwMock,
		&dummyRTPDB{
			getModelFamilyByModel: func(ctx context.Context, modelID uint64) (*rtpdb_models.ModelFamily, error) {
				if modelID == 2 {
					return &rtpdb_models.ModelFamily{ID: 1}, nil
				}
				return nil, fmt.Errorf("unexpected modelID: %d", modelID)
			},
		},
		&analysisDataCalculatorMock{},
		fakeGateChecker,
		&scubaMock{},
		"dummy_scuba1",
		hostConfigScubaReporter,
		time.Hour,
		time.Hour,
		10,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, controller)
	defer func() {
		assert.NoError(t, controller.Close())
	}()

	f0e3a10 := rtpfw.Firmware{
		Metadata: rtpfw.FirmwareMeta{
			PCRValues: types.PCRValues{
				{
					Value: mustHexDecode("7AAB0AF6E370D9A9A27ACF15911FC4EE146A2BE0"),
					Properties: types.Properties{
						types.PropertyIntelTXT(false),
					},
				},
			},
		},
		ImageFile: rtpfw.ImageFile{
			Name: "F0E_3A10.bin",
			Data: make([]byte, 100),
		},
	}
	rtpfwMock.add("F0E_3A10", "18/02/2021", &[]uint64{1}[0], f0e3a10)

	rtpfwMock.upsertPCRs = func(ctx context.Context, controlPCR []byte, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, pcrs rtpfw.PCRValues, updateTags bool, forcedTags ...types.MeasurementTag) error {
		require.Fail(t, "insert PCR0 should not be called")
		return nil
	}
	resultPCR0, err := controller.ReportHostConfiguration(
		context.Background(),
		&afas.HostInfo{
			ModelID: &[]int32{2}[0],
		},
		"F0E_3A10", "18/02/2021",
		tpmdetection.TypeTPM20,
		nil, nil, nil,
	)
	require.ErrorAs(t, err, &ErrParseOrigFirmware{})
	require.Empty(t, resultPCR0.PCR0SHA1)
	require.Empty(t, resultPCR0.PCR0SHA256)

	require.Len(t, hostConfigScubaReporter.loggedItems, 1)
}

func TestReportIncorrectHostConfiguration(t *testing.T) {
	ctx := observability.WithBelt(
		context.Background(), logger.LevelTrace,
		"", "", "",
		"unit-test", true,
	)

	// gating setup
	gate := "ramdisk_attestation_report_config"
	fakeGateChecker := gatingMocks.NewFakeGateChecker()
	fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

	rtpfwMock := newRTPFWMock()
	hostConfigScubaReporter := &scubaMock{}
	controller, err := newInternal(
		context.Background(),
		0,
		&storageMock{},
		newSERFMock(),
		&firmwareStorageMock{},
		&rfeMock{},
		rtpfwMock,
		&dummyRTPDB{
			getModelFamilyByModel: func(ctx context.Context, modelID uint64) (*rtpdb_models.ModelFamily, error) {
				if modelID == 123 {
					return &rtpdb_models.ModelFamily{ID: 1}, nil
				}
				return nil, fmt.Errorf("unexpected modelID: %d", modelID)
			},
		},
		&analysisDataCalculatorMock{},
		fakeGateChecker,
		&scubaMock{},
		"dummy_scuba1",
		hostConfigScubaReporter,
		time.Hour,
		time.Hour,
		10,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, controller)
	defer func() {
		assert.NoError(t, controller.Close())
	}()

	firmwareImage, err := samples.GetFile("firmwares", "F0E_3A10.bin.xz")
	require.NoError(t, err)

	const correctACMPolicyStatusRegisterValue = 0x0000000200108681

	fw, err := uefi.ParseUEFIFirmwareBytes(firmwareImage)
	require.NoError(t, err)

	modifiedFirmwareImagePCR0 := func(originalImage []byte) []byte {
		regs := registers.Registers{registers.ParseACMPolicyStatusRegister(correctACMPolicyStatusRegisterValue)}

		// TODO: replace this with firmware.Tamper when D36165396 will land
		result := measurements.SimulateBootProcess(
			ctx,
			biosimage.NewFromParsed(fw),
			regs,
			flows.IntelCBnT,
		)
		require.NoError(t, result.Log.Error())

		var dxeMeasurement *bootflowtypes.MeasuredData
	loop_find_dxe_measurement:
		for idx := range result.CurrentState.MeasuredData {
			m := &result.CurrentState.MeasuredData[idx]
			switch dataSource := m.DataSource.(type) {
			case datasources.UEFIGUIDFirst:
				if dataSource[0].String() == ffsConsts.GUIDDXEContainer.String() {
					dxeMeasurement = m
					break loop_find_dxe_measurement
				}
			}
		}
		require.NotNil(t, dxeMeasurement)
		refs := dxeMeasurement.References()
		require.NoError(t, refs.Resolve())

		modifiedFirmwareImage := make([]byte, len(fw.Buf()))
		copy(modifiedFirmwareImage, fw.Buf())
		var modified bool
		for _, r := range refs.Ranges() {
			modifiedFirmwareImage[r.Offset]++
			modified = true
			break
		}
		require.True(t, modified)

		modifiedFirmware, err := uefi.ParseUEFIFirmwareBytes(modifiedFirmwareImage)
		require.NoError(t, err)

		pcr0Value, err := measurements.CalculatePCR0(
			ctx,
			modifiedFirmware,
			flows.IntelCBnT,
			regs,
			tpm2.AlgSHA256,
		)
		require.NoError(t, err)
		return pcr0Value
	}(firmwareImage)

	f0e3a10 := rtpfw.Firmware{
		Metadata: rtpfw.FirmwareMeta{
			PCRValues: types.PCRValues{
				{
					Value: mustHexDecode("7AAB0AF6E370D9A9A27ACF15911FC4EE146A2BE0"),
					Properties: types.Properties{
						types.PropertyIntelTXT(false),
					},
				},
			},
		},
		ImageFile: rtpfw.ImageFile{
			Name: "F0E_3A10.bin",
			Data: firmwareImage,
		},
	}
	rtpfwMock.add("F0E_3A10", "18/02/2021", &[]uint64{1}[0], f0e3a10)

	rtpfwMock.upsertPCRs = func(ctx context.Context, controlPCR []byte, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, pcrs rtpfw.PCRValues, updateTags bool, forcedTags ...types.MeasurementTag) error {
		require.Fail(t, "insert PCR0 should not be called")
		return nil
	}

	hostname := "some-host.prn.facebook.com"
	assetID := int64(1)
	modelID := int32(123)
	hostInfo := &afas.HostInfo{
		Hostname: &hostname,
		AssetID:  &assetID,
		ModelID:  &modelID,
	}
	resultPCR0, err := controller.ReportHostConfiguration(context.Background(), hostInfo, "F0E_3A10", "18/02/2021", tpmdetection.TypeTPM20, []*afas.StatusRegister{{Id: "ACM_POLICY_STATUS", Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}}}, nil, modifiedFirmwareImagePCR0)
	require.ErrorAs(t, err, &ErrInvalidHostConfiguration{})
	require.Empty(t, resultPCR0.PCR0SHA1)
	require.Empty(t, resultPCR0.PCR0SHA256)

	require.Len(t, hostConfigScubaReporter.loggedItems, 1)
}

func mustHexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("failed to hexdecode: '%s': %v", s, err))
	}
	return data
}

type dummyRTPDB struct {
	getFirmwares          func(ctx context.Context, filters ...rtpdb.Filter) ([]rtpdb_models.Firmware, error)
	getModelFamilyByModel func(ctx context.Context, modelID uint64) (*rtpdb_models.ModelFamily, error)
}

func (d dummyRTPDB) GetFirmwares(ctx context.Context, filters ...rtpdb.Filter) ([]rtpdb_models.Firmware, error) {
	return d.getFirmwares(ctx, filters...)
}

func (d dummyRTPDB) GetModelFamilyByModel(ctx context.Context, modelID uint64) (*rtpdb_models.ModelFamily, error) {
	if d.getModelFamilyByModel == nil {
		return nil, fmt.Errorf("mock function is not defined")
	}
	return d.getModelFamilyByModel(ctx, modelID)
}

func (d dummyRTPDB) Close() error {
	return nil
}

type storageMock struct {
	storageInterface
	get                 func(ctx context.Context, imageID types.ImageID) ([]byte, *models.ImageMetadata, error)
	insert              func(ctx context.Context, imageMeta models.ImageMetadata, imageData []byte) error
	insertAnalyzeReport func(ctx context.Context, report *models.AnalyzeReport) error
	findOne             func(ctx context.Context, filters storage.FindFilter) (*models.ImageMetadata, context.CancelFunc, error)
}

func (sm storageMock) Get(ctx context.Context, imageID types.ImageID) ([]byte, *models.ImageMetadata, error) {
	if sm.get == nil {
		return nil, nil, nil
	}
	return sm.get(ctx, imageID)
}

func (sm storageMock) Insert(ctx context.Context, imageMeta models.ImageMetadata, imageData []byte) error {
	if sm.insert == nil {
		return nil
	}
	return sm.insert(ctx, imageMeta, imageData)
}

func (sm storageMock) UpsertReproducedPCRs(ctx context.Context, reproducedPCRs models.ReproducedPCRs) error {
	return nil
}

func (sm storageMock) Close() error {
	return nil
}

func (sm storageMock) InsertAnalyzeReport(ctx context.Context, report *models.AnalyzeReport) error {
	if sm.insertAnalyzeReport == nil {
		return nil
	}
	return sm.insertAnalyzeReport(ctx, report)
}

func (sm storageMock) FindOne(ctx context.Context, filters storage.FindFilter) (*models.ImageMetadata, context.CancelFunc, error) {
	if sm.findOne == nil {
		return nil, nil, storage.ErrNotFound{}
	}
	return sm.findOne(ctx, filters)
}

type scubaMock struct {
	loggedItems []interface{}
}

func (sm *scubaMock) Log(v interface{}) error {
	sm.loggedItems = append(sm.loggedItems, v)
	return nil
}

func (sm *scubaMock) Close() error {
	return nil
}

type serfMock struct {
	deviceByHostname map[string]*device.Device
	deviceByAssetID  map[int64]*device.Device
}

func (s *serfMock) GetDeviceByName(hostname string) (*device.Device, error) {
	if d, found := s.deviceByHostname[hostname]; found {
		return d, nil
	}
	return nil, fmt.Errorf("not found")
}

func (s *serfMock) GetDeviceById(assetID int64) (*device.Device, error) {
	if d, found := s.deviceByAssetID[assetID]; found {
		return d, nil
	}
	return nil, fmt.Errorf("not found")

}

func (s *serfMock) Close() error {
	return nil
}

func newSERFMock() *serfMock {
	return &serfMock{
		deviceByHostname: make(map[string]*device.Device),
		deviceByAssetID:  make(map[int64]*device.Device),
	}
}

type rfeMock struct {
	rfeInterface
}

type fetchedFirmware struct {
	filename string
	data     []byte
}

type firmwareStorageMock struct {
	firmwarestorage.FirmwareStorage
}

type firmwareKey struct {
	version       string
	date          string
	modelFamilyID uint64
}

type rtpfwMock struct {
	upsertPCRs func(
		ctx context.Context,
		controlPCR []byte,
		firmwareVersion, firmwareDateString string,
		modelFamilyID *uint64,
		pcrs rtpfw.PCRValues,
		updateTags bool,
		forcedTags ...types.MeasurementTag,
	) error
	firmwares map[firmwareKey]rtpfw.Firmware
}

func (rm *rtpfwMock) add(firmwareVersion, firmwareDateString string, modelFamilyID *uint64, firmware rtpfw.Firmware) {
	key := firmwareKey{
		version:       firmwareVersion,
		date:          firmwareDateString,
		modelFamilyID: uint64deref(modelFamilyID),
	}
	rm.firmwares[key] = firmware
}

func (rm *rtpfwMock) Update(ctx context.Context) (bool, error) {
	return false, nil
}

func (rm *rtpfwMock) GetFirmware(
	ctx context.Context,
	firmwareVersion, firmwareDateString string,
	modelFamilyID *uint64,
	evaluationStatus rtp.EvaluationStatus,
	_ types.CachingPolicy,
) (rtpfw.Firmware, error) {
	key := firmwareKey{
		version:       firmwareVersion,
		date:          firmwareDateString,
		modelFamilyID: uint64deref(modelFamilyID),
	}
	result, found := rm.firmwares[key]
	if !found {
		return rtpfw.Firmware{}, fmt.Errorf("not found")
	}
	return result, nil
}

func (rm *rtpfwMock) UpsertPCRs(
	ctx context.Context,
	controlPCR []byte,
	firmwareVersion, firmwareDateString string,
	modelFamilyID *uint64,
	evaluationStatus rtp.EvaluationStatus,
	pcrs rtpfw.PCRValues,
	updateTags bool,
	forcedTags ...types.MeasurementTag,
) error {
	return rm.upsertPCRs(ctx, controlPCR, firmwareVersion, firmwareDateString, modelFamilyID, pcrs, updateTags, forcedTags...)
}

func newRTPFWMock() *rtpfwMock {
	return &rtpfwMock{
		firmwares: make(map[firmwareKey]rtpfw.Firmware),
	}
}

type analysisDataCalculatorMock struct {
	calculate func(ctx context.Context, t reflect.Type, in analysis.Input, cache analysis.DataCache) (reflect.Value, []analysis.Issue, error)
}

var _ analysisDataCalculatorInterface = (*analysisDataCalculatorMock)(nil)

func (em *analysisDataCalculatorMock) Calculate(
	ctx context.Context,
	t reflect.Type,
	in analysis.Input, cache analysis.DataCache,
) (reflect.Value, []analysis.Issue, error) {
	if em.calculate == nil {
		panic("analysisDataCalculatorMock.calculator is not set")
	}
	return em.calculate(ctx, t, in, cache)
}

package controller

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/rtp"
	gatingMocks "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/gating/mocks"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpfw"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestControllerCreation(t *testing.T) {
	storage := &storageMock{}
	serf := &serfMock{}
	firmwareStorage := &firmwareStorageMock{}

	rfe := &rfeMock{}
	_rtpfw := newRTPFWMock()

	diffScubaReporter := &scubaMock{}
	hostConfigScubaReporter := &scubaMock{}
	dataCalculatorMock := &analysisDataCalculatorMock{}

	// gating setup
	gate := "ramdisk_attestation_report_config"
	fakeGateChecker := gatingMocks.NewFakeGateChecker()
	fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

	t.Run("successfull", func(t *testing.T) {
		controller, err := newInternal(
			context.Background(),
			0,
			storage,
			serf,
			firmwareStorage,
			rfe,
			_rtpfw,
			&dummyRTPDB{},
			dataCalculatorMock,
			fakeGateChecker,
			diffScubaReporter,
			"dummy_scuba1",
			hostConfigScubaReporter,
			time.Hour,
			time.Hour,
			10,
			10,
		)
		require.NoError(t, err)
		require.NotNil(t, controller)
		require.NoError(t, controller.Close())
	})

	t.Run("api_purge_bigger_rtpfw_timeout", func(t *testing.T) {
		controller, err := newInternal(
			context.Background(),
			0,
			storage,
			serf,
			firmwareStorage,
			rfe,
			_rtpfw,
			&dummyRTPDB{},
			dataCalculatorMock,
			fakeGateChecker,
			diffScubaReporter,
			"dummy_scuba1",
			hostConfigScubaReporter,
			time.Hour,
			2*time.Hour,
			10,
			10,
		)
		require.Error(t, err)
		require.Nil(t, controller)
	})
}

// Creates a controller instance or dies trying. Uses reasonable defaults.
func makeController(t *testing.T) *Controller {
	ctx := observability.WithBelt(context.Background(), logger.LevelTrace, "", "", "", "unittest", true)

	storage := &storageMock{}
	serf := &serfMock{}
	firmwareStorage := &firmwareStorageMock{}

	rfe := &rfeMock{}
	_rtpfw := newRTPFWMock()

	diffScubaReporter := &scubaMock{}
	hostConfigScubaReporter := &scubaMock{}
	executorMock := &analysisDataCalculatorMock{}

	// gating setup
	gate := "ramdisk_attestation_report_config"
	fakeGateChecker := gatingMocks.NewFakeGateChecker()
	fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

	ctl, err := newInternal(
		ctx,
		0,
		storage,
		serf,
		firmwareStorage,
		rfe,
		_rtpfw,
		&dummyRTPDB{},
		executorMock,
		fakeGateChecker,
		diffScubaReporter,
		"dummy_scuba1",
		hostConfigScubaReporter,
		time.Hour,
		time.Hour,
		10,
		10,
	)

	if err != nil {
		t.Fatal(err)
	}

	return ctl
}

func TestCloseWaitsForAsync(t *testing.T) {
	t.Run("well_behaved", func(t *testing.T) {
		ctl := makeController(t)
		counter := 0
		done := make(chan struct{})
		ctl.launchAsync(ctl.Context, func(ctx context.Context) {
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			defer close(done)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					counter++ // busywork - not important
				}
			}
		})

		require.NoError(t, ctl.Close(), "wanted nil, because it's the first call to Close")

		timeout := time.NewTimer(time.Second)
		defer timeout.Stop()
		select {
		case <-done:
		case <-timeout.C:
			t.Error("goroutine failed to rejoin after Close returned")
		}
	})

	t.Run("racing_close", func(t *testing.T) {
		ctl := makeController(t)

		// Close the controller when the number of outstanding routines exceeds 100.
		var racyRoutineCount int64
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Do this in a hot loop, because it will happen /fast/.
			for {
				if n := atomic.LoadInt64(&racyRoutineCount); n > 100 {
					t.Logf("calling Close after %d goroutines", n)
					require.NoError(t, ctl.Close())
					return
				}
			}
		}()
		for {
			err := ctl.launchAsync(ctl.Context, func(ctx context.Context) {
				select {
				case <-done:
					t.Error("Close() returned before a goroutine started")
				default:
				}

				<-ctx.Done()

				select {
				case <-done:
					t.Error("Close() returned before a goroutine returned")
				default:
				}
			})
			if err != nil {
				break
			}
			atomic.AddInt64(&racyRoutineCount, 1)
		}

		timeout := time.NewTimer(time.Second)
		defer timeout.Stop()
		select {
		case <-done:
		case <-timeout.C:
			t.Error("Close() failed to return")
		}
	})
}

func TestGetFirmwareHelper(t *testing.T) {
	createController := func(rtpfw rtpfwInterface) (*Controller, error) {
		storage := &storageMock{}
		serf := &serfMock{}
		firmwareStorage := &firmwareStorageMock{}
		rfe := &rfeMock{}
		diffScubaReporter := &scubaMock{}
		hostConfigScubaReporter := &scubaMock{}
		executorMock := &analysisDataCalculatorMock{}

		// gating setup
		gate := "ramdisk_attestation_report_config"
		fakeGateChecker := gatingMocks.NewFakeGateChecker()
		fakeGateChecker.On("CheckAssetID", gate, mock.Anything).Return(true)

		return newInternal(
			context.Background(),
			0,
			storage,
			serf,
			firmwareStorage,
			rfe,
			rtpfw,
			&dummyRTPDB{},
			executorMock,
			fakeGateChecker,
			diffScubaReporter,
			"dummy_scuba1",
			hostConfigScubaReporter,
			time.Hour,
			time.Hour,
			10,
			10,
		)
	}

	rtpfwMock := &rtpFWMockedImpl{
		update: func(ctx context.Context) (bool, error) {
			require.Fail(t, "Update should not be called")
			return false, fmt.Errorf("Update should not be called")
		},
		upsertPCRs: func(ctx context.Context, controlPCR []byte, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, evaluationStatus rtp.EvaluationStatus,
			pcrs rtpfw.PCRValues, updateTags bool, forcedTags ...types.MeasurementTag) error {

			require.Fail(t, "Upsert should not be called")
			return fmt.Errorf("Upsert should not be called")
		},
	}

	t.Run("UnknownError", func(t *testing.T) {
		var getFirmwareCalled int
		rtpfwMock.getFirmware = func(ctx context.Context, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, evaluationStatus rtp.EvaluationStatus, chp types.CachingPolicy) (rtpfw.Firmware, error) {
			getFirmwareCalled++
			return rtpfw.Firmware{}, fmt.Errorf("Some error")
		}
		controller, err := createController(rtpfwMock)
		require.NoError(t, err)
		require.NotNil(t, controller)
		defer func() {
			assert.NoError(t, controller.Close())
		}()

		_, err = getRTPFirmware(context.Background(), controller.rtpfw, "fw_version", "fw_date", &[]uint64{1}[0], rtp.EvaluationStatus_MASS_PRODUCTION, types.CachingPolicyDefault)
		require.Error(t, err)
		require.Equal(t, 1, getFirmwareCalled)
	})

	t.Run("NoFirmware", func(t *testing.T) {
		var getFirmwareCalled int
		rtpfwMock.getFirmware = func(ctx context.Context, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, evaluationStatus rtp.EvaluationStatus, chp types.CachingPolicy) (rtpfw.Firmware, error) {
			getFirmwareCalled++
			require.LessOrEqual(t, getFirmwareCalled, 2)
			if getFirmwareCalled == 1 {
				return rtpfw.Firmware{}, rtpfw.ErrNotFound{}
			}
			require.Equal(t, rtpfw.EvaluationStatusMostProductionReady, evaluationStatus)
			return rtpfw.Firmware{}, nil
		}
		controller, err := createController(rtpfwMock)
		require.NoError(t, err)
		require.NotNil(t, controller)
		defer func() {
			assert.NoError(t, controller.Close())
		}()

		_, err = getRTPFirmware(context.Background(), controller.rtpfw, "fw_version", "fw_date", &[]uint64{1}[0], rtp.EvaluationStatus_MASS_PRODUCTION, types.CachingPolicyDefault)
		require.NoError(t, err)
		require.Equal(t, 2, getFirmwareCalled)
	})
}

type rtpFWMockedImpl struct {
	update      func(ctx context.Context) (bool, error)
	getFirmware func(ctx context.Context, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, evaluationStatus rtp.EvaluationStatus, chp types.CachingPolicy) (rtpfw.Firmware, error)
	upsertPCRs  func(ctx context.Context, controlPCR []byte, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, evaluationStatus rtp.EvaluationStatus,
		pcrs rtpfw.PCRValues, updateTags bool, forcedTags ...types.MeasurementTag) error
}

func (rm *rtpFWMockedImpl) Update(ctx context.Context) (bool, error) {
	return rm.update(ctx)
}

func (rm *rtpFWMockedImpl) GetFirmware(ctx context.Context, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, evaluationStatus rtp.EvaluationStatus, chp types.CachingPolicy) (rtpfw.Firmware, error) {
	return rm.getFirmware(ctx, firmwareVersion, firmwareDateString, modelFamilyID, evaluationStatus, chp)
}

func (rm *rtpFWMockedImpl) UpsertPCRs(ctx context.Context, controlPCR []byte, firmwareVersion, firmwareDateString string, modelFamilyID *uint64, evaluationStatus rtp.EvaluationStatus,
	pcrs rtpfw.PCRValues, updateTags bool, forcedTags ...types.MeasurementTag) error {
	return rm.upsertPCRs(ctx, controlPCR, firmwareVersion, firmwareDateString, modelFamilyID, evaluationStatus, pcrs, updateTags, forcedTags...)
}

package analysis

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDataCalculatorCreation(t *testing.T) {
	t.Run("with_cache", func(t *testing.T) {
		dataCalc, err := NewDataCalculator(10)
		require.NoError(t, err)
		require.NotNil(t, dataCalc)
	})

	t.Run("without_cache", func(t *testing.T) {
		dataCalc, err := NewDataCalculator(0)
		require.NoError(t, err)
		require.NotNil(t, dataCalc)
	})
}

func TestCalcUnknownValue(t *testing.T) {
	dataCalc, err := NewDataCalculator(0)
	require.NoError(t, err)
	require.NotNil(t, dataCalc)

	v, issues, err := dataCalc.Calculate(context.Background(), reflect.TypeOf("dummy"), NewInput(), nil)
	require.ErrorAs(t, err, &ErrCalcNotSupported{})
	require.Empty(t, issues)
	require.Equal(t, reflect.Invalid, v.Kind())
}

func TestCalculationError(t *testing.T) {
	dataCalc, err := NewDataCalculator(10)
	require.NoError(t, err)
	require.NotNil(t, dataCalc)

	var calcCalledCount int
	err = SetValueCalculator(dataCalc, func(ctx context.Context, in dummyInput) (dummyOutput, []Issue, error) {
		calcCalledCount++
		return dummyOutput{}, nil, fmt.Errorf("dummy error")
	})
	require.NoError(t, err)

	v, issues, err := dataCalc.Calculate(context.Background(), reflect.TypeOf(dummyOutput{}), NewInput(), nil)
	require.Error(t, err)
	require.Empty(t, issues)
	require.Equal(t, reflect.Invalid, v.Kind())

	require.Equal(t, 0, dataCalc.cache.Len())
	require.Empty(t, dataCalc.runtime)
}

func TestGlobalCacheUsed(t *testing.T) {
	dataCalc, err := NewDataCalculator(10)
	require.NoError(t, err)
	require.NotNil(t, dataCalc)

	var calcCalledCount int
	err = SetValueCalculator(dataCalc, func(ctx context.Context, in dummyInput) (dummyOutput, []Issue, error) {
		calcCalledCount++
		return dummyOutput{}, nil, nil
	})
	require.NoError(t, err)

	v, issues, err := dataCalc.Calculate(context.Background(), reflect.TypeOf(dummyOutput{}), NewInput(), nil)
	require.NoError(t, err)
	require.Empty(t, issues)
	require.Equal(t, dummyOutput{}, v.Interface())

	v, issues, err = dataCalc.Calculate(context.Background(), reflect.TypeOf(dummyOutput{}), NewInput(), nil)
	require.NoError(t, err)
	require.Empty(t, issues)
	require.Equal(t, dummyOutput{}, v.Interface())

	require.Equal(t, 1, calcCalledCount)

	cacheItem := newGlobalCacheItem(
		reflect.ValueOf(AlignedOriginalFirmware{}),
		nil,
	)
	require.NotNil(t, cacheItem)

	require.Empty(t, dataCalc.runtime)
}

func TestLargeObjectsAreNotSavedInGlobalCache(t *testing.T) {
	dataCalc, err := NewDataCalculator(10)
	require.NoError(t, err)
	require.NotNil(t, dataCalc)

	var calcCalledCount int
	delete(dataCalc.valueCalculators, reflect.TypeOf((*OriginalFirmware)(nil)).Elem())
	err = SetValueCalculator(dataCalc, func(ctx context.Context, in dummyInput) (*OriginalFirmware, []Issue, error) {
		calcCalledCount++
		return (*OriginalFirmware)(nil), nil, nil
	})
	require.NoError(t, err)

	v, issues, err := dataCalc.Calculate(context.Background(), reflect.TypeOf((*OriginalFirmware)(nil)).Elem(), NewInput(), nil)
	require.NoError(t, err)
	require.Empty(t, issues)
	require.Equal(t, (*OriginalFirmware)(nil), v.Interface())

	v, issues, err = dataCalc.Calculate(context.Background(), reflect.TypeOf((*OriginalFirmware)(nil)).Elem(), NewInput(), nil)
	require.NoError(t, err)
	require.Empty(t, issues)
	require.Equal(t, (*OriginalFirmware)(nil), v.Interface())

	require.Equal(t, 2, calcCalledCount)
	require.Empty(t, dataCalc.runtime)
}

func TestExternalCacheUsed(t *testing.T) {
	var calcCalledCount int

	createDataCalc := func() *DataCalculator {
		dataCalc, err := NewDataCalculator(10)
		require.NoError(t, err)
		require.NotNil(t, dataCalc)

		err = SetValueCalculator(dataCalc, func(ctx context.Context, in dummyInput) (dummyOutput, []Issue, error) {
			calcCalledCount++
			return dummyOutput{}, nil, nil
		})
		require.NoError(t, err)
		return dataCalc
	}

	cache := newDataCache()
	require.NotNil(t, cache)

	dataCalc := createDataCalc()
	v, issues, err := dataCalc.Calculate(context.Background(), reflect.TypeOf(dummyOutput{}), NewInput(), cache)
	require.NoError(t, err)
	require.Empty(t, issues)
	require.Equal(t, dummyOutput{}, v.Interface())

	require.Equal(t, 1, calcCalledCount)
	require.Empty(t, dataCalc.runtime)

	require.Len(t, cache.cache, 1)

	// re-create datacalc to remove all side-effects
	dataCalc = createDataCalc()
	v, issues, err = dataCalc.Calculate(context.Background(), reflect.TypeOf(dummyOutput{}), NewInput(), cache)
	require.NoError(t, err)
	require.Empty(t, issues)
	require.Equal(t, dummyOutput{}, v.Interface())

	require.Equal(t, 1, calcCalledCount)
	require.Empty(t, dataCalc.runtime)
}

func TestRuntimeCache(t *testing.T) {
	dataCalc, err := NewDataCalculator(10)
	require.NoError(t, err)
	require.NotNil(t, dataCalc)

	calcInvokedCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calculatorBarrier := make(chan struct{})

	err = SetValueCalculator(dataCalc, func(ctx context.Context, in dummyInput) (dummyOutput, []Issue, error) {
		cancel()
		<-calculatorBarrier
		return dummyOutput{}, nil, nil
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	launchCalculateAsync := func() {
		wg.Add(1)
		go func() {
			defer wg.Done()

			v, issues, err := dataCalc.Calculate(context.Background(), reflect.TypeOf(dummyOutput{}), NewInput(), nil)
			require.NoError(t, err)
			require.Empty(t, issues)
			require.Equal(t, dummyOutput{}, v.Interface())
		}()
	}

	launchCalculateAsync()
	// wait for calculator to be invoked, at this time the runtime cache should be used
	<-calcInvokedCtx.Done()

	// launch second time that should hit runtime cache
	launchCalculateAsync()
	time.Sleep(10 * time.Millisecond)

	close(calculatorBarrier)
	wg.Wait()
}

type dummyInput struct{}

type dummyOutput struct{}

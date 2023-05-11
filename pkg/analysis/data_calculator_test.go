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

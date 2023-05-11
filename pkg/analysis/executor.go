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
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/facebookincubator/go-belt/tool/experimental/errmon"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"
)

// DataCalculatorInterface calculates intermediate results that could be reused, like: measurements flow, fixed registers
type DataCalculatorInterface interface {
	Calculate(ctx context.Context, t reflect.Type, in Input, cache DataCache) (reflect.Value, []Issue, error)
}

// ExecuteAnalyzer invokes analysis of a single given Analyzer
func ExecuteAnalyzer[analyzerInputType any](
	ctx context.Context,
	dataCalculator DataCalculatorInterface,
	analyzer Analyzer[analyzerInputType],
	in Input,
	cache DataCache,
) (retReport *Report, retErr error) {
	defer func() {
		if newErr := errmon.ObserveRecoverCtx(ctx, recover()).AsError(); newErr != nil {
			retErr = newErr
		}
	}()

	// TODO: replace reflection with generics:
	analyzeMethod := reflect.ValueOf(analyzer.Analyze)

	var argIssues []Issue
	intPtr, argIssues, err := resolveInputStruct(ctx, analyzeMethod.Type().In(1), in, newUniqueTypeDataCache(cache), dataCalculator)
	if err != nil {
		return nil, ErrResolveInput{Err: err}
	}

	report, err := analyzer.Analyze(ctx, intPtr.Elem().Interface().(analyzerInputType))
	if err != nil {
		return nil, ErrAnalyze{Err: err}
	}
	report.Issues = uniqueIssues(append(report.Issues, argIssues...))
	return report, nil
}

// uniqueTypeDataCache is a fast cache implementation for single analyzer execution as it operates on a fixed input
type uniqueTypeDataCache struct {
	cache     map[reflect.Type]*CachedValue
	nextCache DataCache
}

func newUniqueTypeDataCache(nextCache DataCache) DataCache {
	return &uniqueTypeDataCache{
		cache:     make(map[reflect.Type]*CachedValue),
		nextCache: nextCache,
	}
}

func (c *uniqueTypeDataCache) Get(t reflect.Type, inputHash *objhash.ObjHash) *CachedValue {
	if v, found := c.cache[t]; found {
		return v
	}
	if c.nextCache != nil {
		return c.nextCache.Get(t, inputHash)
	}
	return nil
}

func (c *uniqueTypeDataCache) Set(t reflect.Type, inputHash objhash.ObjHash, val *CachedValue) {
	c.cache[t] = val
	if c.nextCache != nil {
		c.nextCache.Set(t, inputHash, val)
	}
}

func findType(ctx context.Context, t reflect.Type, in Input, cache DataCache) *CachedValue {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if v, found := in[typeToID(t)]; found {
		return &CachedValue{Val: reflect.ValueOf(v)}
	}
	if cache != nil {
		return cache.Get(t, nil)
	}
	return nil
}

func resolveType(
	ctx context.Context,
	t reflect.Type,
	in Input,
	cache DataCache,
	dc DataCalculatorInterface,
) (reflect.Value, []Issue, error) {
	if res := findType(ctx, t, in, cache); res != nil {
		return res.Val, res.Issues, res.Err
	}
	v, issues, err := dc.Calculate(ctx, t, in, cache)
	if errors.As(err, &ErrCalcNotSupported{}) {
		err = ErrMissingInput{missingType: t.String(), providedInput: in}
	}
	return v, issues, err
}

// resolveInputStruct tries to fill a structure of type t with values for types that should be either provided as input to Executor
// or be calculated using functions provided to addValueCalculator method
func resolveInputStruct(
	ctx context.Context,
	t reflect.Type,
	in Input,
	cache DataCache,
	dc DataCalculatorInterface,
) (reflect.Value, []Issue, error) {
	if t.Kind() != reflect.Struct {
		return reflect.Value{}, nil, fmt.Errorf("input type is not a structure, but '%v", t.Kind())
	}

	var argIssues []Issue
	intPtr := reflect.New(t)
	for idx := 0; idx < t.NumField(); idx++ {
		valueField := intPtr.Elem().Field(idx)
		v, issues, err := resolveType(ctx, valueField.Type(), in, cache, dc)
		if err != nil {
			// it is ok to get an error for an optional field
			typeField := t.Field(idx)
			tags := strings.Split(typeField.Tag.Get("exec"), ",")
			if !isOptional(tags) {
				return reflect.Value{}, nil, ErrResolveValue{FieldName: typeField.Name, TypeName: typeField.Type.Name(), Err: err}
			}
			continue
		}
		argIssues = append(argIssues, issues...)
		switch {
		case v.Kind() == valueField.Kind():
		case v.Kind() == reflect.Pointer:
			v = v.Elem()
		case valueField.Kind() == reflect.Pointer:
			if v.CanAddr() {
				v = v.Addr()
			} else {
				newV := reflect.New(v.Type())
				newV.Elem().Set(v)
				v = newV
			}
		default:
			return reflect.Value{}, nil, fmt.Errorf("do not know how to assign %T to %T", v.Interface(), valueField.Interface())
		}
		valueField.Set(v)
	}
	return intPtr, uniqueIssues(argIssues), nil
}

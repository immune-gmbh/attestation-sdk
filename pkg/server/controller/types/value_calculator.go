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
package types

import (
	"context"
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/dmidecode"
	"github.com/immune-gmbh/attestation-sdk/pkg/uefi"

	"github.com/facebookincubator/go-belt/tool/logger"
)

// OverrideValueCalculators adds value calculators.
//
// This is moved out of `analysis` package, because this calculators contains
// optional knowledge `analysis` should be agnostic about.
// Currently these calculators just enable more caching to improve the performance.
func OverrideValueCalculators(dc *analysis.DataCalculator) {
	analysis.SetValueCalculator(dc, getActualFirmware)
	analysis.SetValueCalculator(dc, getOriginalFirmware)
	analysis.SetValueCalculator(dc, getActualBIOSInfo)
	analysis.SetValueCalculator(dc, getOriginalBIOSInfo)
}

// biosInfoCacheInterface defines an interface where there BIOSInfo cache could be extracted from
type biosInfoCacheInterface interface {
	BIOSInfoCache() *dmidecode.BIOSInfo
}

type getActualBIOSInfoInput struct {
	ActualFirmwareBlob analysis.ActualFirmwareBlob
}

func getActualBIOSInfo(ctx context.Context, in getActualBIOSInfoInput) (analysis.ActualBIOSInfo, []analysis.Issue, error) {
	if cacheAccessor, ok := in.ActualFirmwareBlob.Blob.(biosInfoCacheInterface); ok {
		if biosInfo := cacheAccessor.BIOSInfoCache(); biosInfo != nil {
			return *analysis.NewActualBIOSInfo(*biosInfo), nil, nil
		}
		logger.FromCtx(ctx).Debugf("no BIOSInfo cache")
	}

	r, err := dmidecode.DMITableFromFirmwareImage(in.ActualFirmwareBlob.Bytes())
	if err != nil {
		return analysis.ActualBIOSInfo{}, nil, err
	}
	return *analysis.NewActualBIOSInfo(r.BIOSInfo()), nil, nil
}

type getOriginalBIOSInfoInput struct {
	OriginalFirmwareBlob analysis.OriginalFirmwareBlob
}

func getOriginalBIOSInfo(ctx context.Context, in getOriginalBIOSInfoInput) (analysis.OriginalBIOSInfo, []analysis.Issue, error) {
	if cacheAccessor, ok := in.OriginalFirmwareBlob.Blob.(biosInfoCacheInterface); ok {
		if biosInfo := cacheAccessor.BIOSInfoCache(); biosInfo != nil {
			return *analysis.NewOriginalBIOSInfo(*biosInfo), nil, nil
		}
		logger.FromCtx(ctx).Debugf("no BIOSInfo cache")
	}

	r, err := dmidecode.DMITableFromFirmwareImage(in.OriginalFirmwareBlob.Bytes())
	if err != nil {
		return analysis.OriginalBIOSInfo{}, nil, err
	}
	return *analysis.NewOriginalBIOSInfo(r.BIOSInfo()), nil, nil

}

type parsedFirmwareCacheInterface interface {
	ParsedCache() *uefi.UEFI
}

type actualFirmwareInput struct {
	ActualFirmwareBlob analysis.ActualFirmwareBlob
}

func getActualFirmware(ctx context.Context, in actualFirmwareInput) (analysis.ActualFirmware, []analysis.Issue, error) {
	log := logger.FromCtx(ctx)
	if cacheAccessor, ok := in.ActualFirmwareBlob.Blob.(parsedFirmwareCacheInterface); ok {
		if fw := cacheAccessor.ParsedCache(); fw != nil {
			return analysis.NewActualFirmware(fw, in.ActualFirmwareBlob), nil, nil
		}
		log.Debugf("no parsed firmware cache for the actual image")
	}

	fw, err := uefi.Parse(in.ActualFirmwareBlob.Bytes(), false)
	if err != nil {
		err = fmt.Errorf("failed to parse UEFI firmware: %w", err)
		log.Errorf("%v", err)
		return analysis.ActualFirmware{}, nil, err
	}
	return analysis.NewActualFirmware(fw, in.ActualFirmwareBlob), nil, nil
}

type originalFirmwareInput struct {
	OriginalFirmwareBlob analysis.OriginalFirmwareBlob
}

func getOriginalFirmware(ctx context.Context, in originalFirmwareInput) (analysis.OriginalFirmware, []analysis.Issue, error) {
	log := logger.FromCtx(ctx)
	if cacheAccessor, ok := in.OriginalFirmwareBlob.Blob.(parsedFirmwareCacheInterface); ok {
		if fw := cacheAccessor.ParsedCache(); fw != nil {
			return analysis.NewOriginalFirmware(fw, in.OriginalFirmwareBlob), nil, nil
		}
		log.Debugf("no parsed firmware cache for the original image")
	}

	if in.OriginalFirmwareBlob.Blob == nil {
		return analysis.OriginalFirmware{}, nil, fmt.Errorf("no original firmware blob is provided with")
	}

	fw, err := uefi.Parse(in.OriginalFirmwareBlob.Bytes(), false)
	if err != nil {
		err = fmt.Errorf("failed to parse UEFI firmware: %w", err)
		log.Errorf("%v", err)
		return analysis.OriginalFirmware{}, nil, err
	}

	return analysis.NewOriginalFirmware(fw, in.OriginalFirmwareBlob), nil, nil
}

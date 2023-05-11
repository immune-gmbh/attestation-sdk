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
package flashrom

import (
	"context"
	"fmt"

	"github.com/facebookincubator/go-belt/tool/logger"
)

// Dump dumps a firmware image on the local machine
func Dump(ctx context.Context, opts ...Option) ([]byte, error) {
	return newFlashrom(opts...).Dump(ctx)
}

// Dump dumps a firmware image on the local machine
func (f *flashrom) Dump(ctx context.Context) ([]byte, error) {
	switch f.Config.DumpMethod {
	case DumpMethodAuto:
		return f.dumpAuto(ctx)
	case DumpMethodFlashrom:
		return f.dumpFlashrom(ctx)
	case DumpMethodAfulnx64:
		return f.dumpAfulnx64(ctx)
	case DumpMethodDevMem:
		return f.dumpDevMem(ctx)
	case DumpMethodMTD:
		return f.dumpMTD(ctx)
	}
	return nil, fmt.Errorf("invalid dump method: %v", f.Config.DumpMethod)
}

func (f *flashrom) dumpAuto(ctx context.Context) ([]byte, error) {
	imageBytes, flashRomErr := f.dumpFlashrom(ctx)
	logger.FromCtx(ctx).Debugf("flashrom error: %v", flashRomErr)
	if flashRomErr == nil {
		return imageBytes, nil
	}

	if f.Config.Afulnx64Path != `` {
		imageBytes, err := f.dumpAfulnx64(ctx)
		logger.FromCtx(ctx).Debugf("afulnx64 error: %v", err)
		if err == nil {
			return imageBytes, nil
		}
	}

	imageBytes, devMemDumpErr := f.dumpDevMem(ctx)
	logger.FromCtx(ctx).Debugf("'/dev/mem' dumper error: %v", devMemDumpErr)
	if devMemDumpErr == nil {
		return imageBytes, nil
	}
	devMemBytes := imageBytes

	imageBytes, mtdErr := f.dumpMTD(ctx)
	logger.FromCtx(ctx).Debugf("MTD dumper error: %v", mtdErr)
	if mtdErr == nil {
		return imageBytes, nil
	}

	if devMemBytes != nil {
		logger.FromCtx(ctx).Errorf("%v", devMemDumpErr)
		return devMemBytes, nil
	}

	return nil, fmt.Errorf("unable to find a working way to dump the image; flashRomErr: '%v'; devMemDumpErr: '%v', mtdErr: '%v'",
		flashRomErr, devMemDumpErr, mtdErr)
}

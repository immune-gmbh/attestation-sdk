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

	imageBytes, mtdErr := f.dumpMTD(ctx)
	logger.FromCtx(ctx).Debugf("MTD dumper error: %v", mtdErr)
	if mtdErr == nil {
		return imageBytes, nil
	}

	return nil, fmt.Errorf("unable to find a working way to dump the image; flashRomErr: '%v'; devMemDumpErr: '%v', mtdErr: '%v'",
		flashRomErr, devMemDumpErr, mtdErr)
}

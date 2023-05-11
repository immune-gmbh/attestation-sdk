package analysis

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTypesUnique(t *testing.T) {
	checked := []reflect.Type{
		reflect.TypeOf((*OriginalFirmware)(nil)),
		reflect.TypeOf((*OriginalFirmwareBlob)(nil)).Elem(),
		reflect.TypeOf((*ActualFirmware)(nil)),
		reflect.TypeOf((*ActualPSPFirmware)(nil)),
		reflect.TypeOf((*ActualFirmwareBlob)(nil)).Elem(),
		reflect.TypeOf(ActualRegisters{}),
		reflect.TypeOf(FixedRegisters{}),
		reflect.TypeOf(ActualPCR0(nil)),
		reflect.TypeOf(AlignedOriginalFirmware{}),
		reflect.TypeOf(AssetID(0)),
	}

	seen := make(map[reflect.Type]struct{})
	for _, checkedType := range checked {
		if _, found := seen[checkedType]; found {
			require.Fail(t, fmt.Sprintf("type %v is duplicated", checkedType))
		}
		seen[checkedType] = struct{}{}
	}
}

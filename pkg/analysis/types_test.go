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

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
package helpers

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

type Dummy struct {
	ID        uint64 `db:"id,pk"`
	Registers string `db:"registers"`
	Unknown   bool
}

func ptr[T any](a T) *T {
	return &a
}

func TestExtractingColumnName(t *testing.T) {
	column, err := GetDBColumnName(reflect.TypeOf(Dummy{}), "ID")
	require.NoError(t, err)
	require.Equal(t, "id", column)

	column, err = GetDBColumnName(reflect.TypeOf(Dummy{}), "Registers")
	require.NoError(t, err)
	require.Equal(t, "registers", column)

	_, err = GetDBColumnName(reflect.TypeOf(Dummy{}), "Unknown")
	require.NoError(t, err)
	require.Equal(t, "registers", column)

	_, err = GetDBColumnName(reflect.TypeOf(Dummy{}), "BlahBlah")
	require.Error(t, err)
}

func TestGetValuesAndColumns(t *testing.T) {
	d := &Dummy{
		ID:        42,
		Registers: "wow",
		Unknown:   true,
	}

	values, columns, err := GetValuesAndColumns(d, func(fieldName string, value any) bool {
		return fieldName == "Registers"
	})
	require.NoError(t, err)
	require.Len(t, values, len(columns))

	require.Equal(t, ptr(uint64(42)), values[0])
	require.Equal(t, "id", columns[0])

	require.Equal(t, ptr(true), values[1])
	require.Equal(t, "unknown", columns[1])
}

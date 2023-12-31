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
package objhash

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuild(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		v0, err := Build(1, "a", 0.2)
		require.NoError(t, err)
		v1, err := Build(1, 0.2, "a")
		require.NoError(t, err)
		v2, err := Build(1, "b", 0.2)
		require.NoError(t, err)
		v3, err := Build(1, "a", 0.2)
		require.NoError(t, err)

		require.Equal(t, v0, v3, fmt.Sprintf("%X != %X", v0, v3))
		require.NotEqual(t, v0, v1, fmt.Sprintf("%X == %X", v0, v1))
		require.NotEqual(t, v0, v2, fmt.Sprintf("%X == %X", v0, v2))
		require.NotEqual(t, v1, v2, fmt.Sprintf("%X == %X", v1, v2))
	})

	t.Run("struct_slices_ptrs", func(t *testing.T) {
		a := struct {
			Ptrs []*int64
		}{
			Ptrs: []*int64{
				&[]int64{-1}[0],
				&[]int64{0}[0],
				&[]int64{1}[0],
			},
		}

		v0, err := Build(&a)
		require.NoError(t, err)

		*a.Ptrs[0]++

		v1, err := Build(&a)
		require.NoError(t, err)

		*a.Ptrs[0]--

		v2, err := Build(&a)
		require.NoError(t, err)

		v3, err := Build(a)
		require.NoError(t, err)

		require.Equal(t, v0, v2, fmt.Sprintf("%X != %X", v0, v2))
		require.NotEqual(t, v0, v1, fmt.Sprintf("%X == %X", v0, v1))
		require.NotEqual(t, v0, v3, fmt.Sprintf("%X == %X", v0, v3))
		require.NotEqual(t, v1, v3, fmt.Sprintf("%X == %X", v1, v3))
	})

	t.Run("map", func(t *testing.T) {
		m := map[struct{}]struct{}{}
		_, err := Build(m)
		require.Error(t, err)
	})

	t.Run("interface-field", func(t *testing.T) {
		s0 := struct{ V any }{V: 1}
		h0, err := Build(s0)
		require.NoError(t, err)

		s1 := struct{ V any }{V: 1}
		h1, err := Build(s1)
		require.NoError(t, err)
		require.Equal(t, h0, h1)

		s2 := struct{ V any }{V: 2}
		h2, err := Build(s2)
		require.NoError(t, err)
		require.NotEqual(t, h0, h2)
	})

	t.Run("reflect.Value", func(t *testing.T) {
		a := struct {
			Num int
			Str string
		}{
			Num: 1,
			Str: "hello",
		}

		v1, err := Build(a)
		require.NoError(t, err)

		v2, err := Build(reflect.ValueOf(a))
		require.NoError(t, err)

		require.Equal(t, v1, v2)
	})

	t.Run("custom0", func(t *testing.T) {
		a := customStruct{}

		v1, err := Build(a)
		require.NoError(t, err)

		v2, err := Build(1, 2, 3)
		require.NoError(t, err)

		require.Equal(t, v1, v2)
	})

	t.Run("custom1", func(t *testing.T) {
		var a ObjHash

		_, err := Build(a)
		require.NoError(t, err)
	})
}

type customStruct struct{}

func (c customStruct) CacheWrite(b *Builder) error {
	return b.Write(1, 2, 3)
}

func BenchmarkMustBuild(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MustBuild(1, "a", 0.2)
	}
}

func BenchmarkBuilderBuildReset(b *testing.B) {
	builder := NewBuilder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.Build(1, "a", 0.2)
		builder.Reset()
	}
}

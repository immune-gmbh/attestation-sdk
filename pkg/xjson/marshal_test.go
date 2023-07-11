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
package xjson

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type blob []byte

type Struct0 struct {
	Struct1   Struct1
	StructPtr *Struct2
	Iface0    any
	Map       map[string]any
}

type Struct1 struct {
	Iface1 any
	Int0   int `json:"int"`
	Int1   *int
}

type Struct2 struct {
	Iface2 any
}

type Struct3 struct {
	Int2 int
}

type typeIDHandlerT struct{}

func (typeIDHandlerT) TypeIDOf(sample any) (TypeID, error) {
	t := reflect.TypeOf(sample)
	prefix := ""
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
		prefix += "*"
	}
	return TypeID(prefix + t.PkgPath() + "." + t.Name()), nil
}

func (typeIDHandlerT) NewByTypeID(typeID TypeID) (any, error) {
	pointerDepth := 0
	for len(typeID) > 0 && typeID[0] == '*' {
		typeID = typeID[1:]
		pointerDepth++
	}
	obj := newByTypeID(typeID)
	if obj == nil {
		return nil, fmt.Errorf("unregistered TypeID '%s'", typeID)
	}

	v := reflect.ValueOf(obj)
	for i := 0; i < pointerDepth; i++ {
		v = reflect.New(v.Type())
	}

	return v.Interface(), nil
}

func newByTypeID(typeID TypeID) any {
	switch typeID {
	case "github.com/immune-gmbh/attestation-sdk/pkg/xjson.Struct0":
		return &Struct0{}
	case "github.com/immune-gmbh/attestation-sdk/pkg/xjson.Struct1":
		return &Struct1{}
	case "github.com/immune-gmbh/attestation-sdk/pkg/xjson.Struct2":
		return &Struct2{}
	case "github.com/immune-gmbh/attestation-sdk/pkg/xjson.Struct3":
		return &Struct3{}
	case "github.com/immune-gmbh/attestation-sdk/pkg/xjson.blob":
		return &blob{}
	case "int":
		return &[]int{0}[0]
	case "float64":
		return &[]float64{0}[0]
	}
	return nil
}

func TestMarshalUnmarshal(t *testing.T) {
	testObj := Struct0{
		Iface0: Struct3{
			Int2: 5,
		},
		Map: map[string]any{
			"Struct1Key": Struct1{
				Iface1: nil,
				Int0:   6,
				Int1:   &[]int{7}[0],
			},
		},
		Struct1: Struct1{
			Iface1: blob("hello world!"),
			Int0:   1,
			Int1:   nil,
		},
		StructPtr: &Struct2{
			Iface2: &Struct1{
				Iface1: blob("hello again!"),
				Int0:   3,
				Int1:   &[]int{4}[0],
			},
		},
	}

	// == validating that simple json.Marshal&json.Unmarshal is not good enough ==

	b, err := json.Marshal(testObj)
	require.NoError(t, err)

	var cpy Struct0
	err = json.Unmarshal(b, &cpy)
	require.NoError(t, err)

	require.NotEqual(t, testObj, cpy)

	// == now validating that our thing solves the problem ==

	typeIDHandler := typeIDHandlerT{}

	b, err = MarshalWithTypeIDs(testObj, typeIDHandler)
	require.NoError(t, err)

	expectedJSON := `{
		"Iface0": {
		  "github.com/immune-gmbh/attestation-sdk/pkg/xjson.Struct3": {
			"Int2": 5
		  }
		},
		"Map": {
		  "Struct1Key": {
			"github.com/immune-gmbh/attestation-sdk/pkg/xjson.Struct1": {
			  "Iface1": null,
			  "Int1": 7,
			  "int": 6
			}
		  }
		},
		"Struct1": {
		  "Iface1": {
			"github.com/immune-gmbh/attestation-sdk/pkg/xjson.blob": "aGVsbG8gd29ybGQh"
		  },
		  "Int1": null,
		  "int": 1
		},
		"StructPtr": {
		  "Iface2": {
			"*github.com/immune-gmbh/attestation-sdk/pkg/xjson.Struct1": {
			  "Iface1": {
				"github.com/immune-gmbh/attestation-sdk/pkg/xjson.blob": "aGVsbG8gYWdhaW4h"
			  },
			  "Int1": 4,
			  "int": 3
			}
		  }
		}
	  }`
	expectedJSON = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(expectedJSON, " ", ""), "\n", ""), "\t", "")

	require.Equal(t, expectedJSON, string(b))

	cpy = Struct0{}
	err = UnmarshalWithTypeIDs(b, &cpy, typeIDHandler)
	require.NoError(t, err)

	require.Equal(t, testObj, cpy)
}

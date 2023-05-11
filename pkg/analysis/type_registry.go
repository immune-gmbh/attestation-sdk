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
	"path/filepath"
	"reflect"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/xjson"
)

type typeRegistryT map[TypeID]reflect.Type

var (
	typeRegistry = typeRegistryT{}
)

// TypeRegistry returns the TypeIDHandler for xjson package.
func TypeRegistry() xjson.TypeIDHandler {
	return typeRegistry
}

// RegisterType registers the type of the provided sample into
// the registry. It allows to deserialize JSONs into typed values.
//
// The sample may also be given as a (nil) pointer.
func RegisterType(sample any) {
	t := typeOf(sample)
	typeRegistry[typeToID(t)] = t
}

// IsRegisteredType returns true if the type of the provided sample
// is already registered (and could be used in analyzer input/output).
func IsRegisteredType(sample any) bool {
	_, ok := typeRegistry[typeIDOf(sample)]
	return ok
}

var (
	// AutoRegisterTypes automatically registers new types in the
	// type registry on an attempt to get TypeID of an unregistered
	// sample.
	AutoRegisterTypes = false
)

// TypeIDOf returns TypeID of the type of the given sample.
func (typeRegistryT) TypeIDOf(sample any) (TypeID, error) {
	id := typeIDOf(sample)

	if IsRegisteredType(sample) {
		return id, nil
	}
	if !AutoRegisterTypes {
		return "", ErrTypeIDNotRegistered{TypeID: id}
	}

	RegisterType(sample)
	return id, nil
}

func typeIDOf(sample any) TypeID {
	t := typeOf(sample)
	return typeToID(t)
}

// NewByTypeID returns a pointer to a value with a type, defined
func (r typeRegistryT) NewByTypeID(id TypeID) (any, error) {
	t, ok := r[id]
	if !ok {
		return nil, ErrTypeIDNotRegistered{TypeID: id}
	}

	return reflect.New(t).Interface(), nil
}

func typeOf(sample any) reflect.Type {
	t := reflect.ValueOf(sample).Type()
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	return t
}

func typeToID(t reflect.Type) TypeID {
	myPkgPath := reflect.TypeOf(typeRegistry).PkgPath()
	if t.PkgPath() == myPkgPath {
		// If the type is define in this package, then just use its name as the typeID.
		//
		// So that we will tag a type for example as "ActualFirmware"
		// instead of "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis.ActualFirmware",
		return TypeID(t.Name())
	}

	pkgPkgPath := filepath.Dir(myPkgPath)
	if strings.HasPrefix(t.PkgPath(), pkgPkgPath) {
		// If the type is defined in the `pkg` of firmware analyzer, then use
		// the path inside `pkg` as the pkgpath.
		//
		// So that we will tag a type for example as "./analyzers/reproducepcr.ExpectedPCR0"
		// instead of "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/reproducepcr.ExpectedPCR0".
		relativePath := t.PkgPath()[len(pkgPkgPath)+1:]
		return TypeID("./" + relativePath + "." + t.Name())
	}

	// Otherwise use the full path
	return TypeID(t.PkgPath() + "." + t.Name())
}

// TypeID as an unique string of a named type.
type TypeID = xjson.TypeID

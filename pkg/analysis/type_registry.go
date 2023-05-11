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

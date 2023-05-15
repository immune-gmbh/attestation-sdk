package xjson

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/tidwall/gjson"
)

// TypeID is an unique identifier of a type
type TypeID string

// TypeIDOfer is a converter of a sample to its TypeID.
type TypeIDOfer interface {
	// TypeIDOf returns TypeID of the type of the given sample.
	TypeIDOf(sample any) (TypeID, error)
}

// NewByTypeIDer is a factory of a value given its TypeID.
type NewByTypeIDer interface {
	// NewByTypeID returns a pointer to an object of the type specified through TypeID.
	NewByTypeID(TypeID) (any, error)
}

// TypeIDHandler is a bidirectional handler which couples TypeID with a type.
type TypeIDHandler interface {
	TypeIDOfer
	NewByTypeIDer
}

// MarshalWithTypeIDs is similar to json.Marshal, but any interface field
// met in a structure is serialized as a structure containing the type
// identifier and the value. It allows to unmarshal the result without
// loosing typing.
//
// If an interface is met, then instead of marshaling its content directly,
// we resolve its type ID through TypeIDOfer and putting:
//
//	{ResolvedTypeID: {...Content...}}
//
// instead (where ResolvedTypeID is a string containing the TypeID).
//
// For example:
//
//	type Struct {
//	    Field any
//	}
//	xjson.MarshalWithTypeIDs(Struct{Field: Struct{Field: int(1)}}, typeIDOfer)
//
// might be marshalled to
//
//	{"Field": {"Struct": {"Field": {"int": 1}}}}
//
// NOTE! This is not a drop-in replacement for standard json.Marshal.
//
//	It has incompatible behavior.
func MarshalWithTypeIDs(obj any, typeIDOfer TypeIDOfer) ([]byte, error) {
	return marshal(reflect.ValueOf(obj), typeIDOfer)
}

var stringNull = []byte("null")

func marshal(v reflect.Value, typeIDOfer TypeIDOfer) ([]byte, error) {
	// How the function works:
	//
	// We are interested only about structues (and their fields),
	// everything else is handled by standard json.Marshal
	//
	// We just iterate through fields and add TypeIDs if see an interface,
	// otherwise marshal as is.

	switch v.Kind() {
	case reflect.Interface:
		// unwrapping the interface
		v := reflect.ValueOf(v.Interface())
		if !v.IsValid() {
			// there was the untyped nil value behind the interface
			return stringNull, nil
		}
		return marshal(v, typeIDOfer)
	case reflect.Pointer:
		v := v.Elem()
		if !v.IsValid() {
			// is a nil pointer
			return stringNull, nil
		}
		// A pointer may lead to a structure, dereferencing and going deeper.
		return marshal(v, typeIDOfer)
	case reflect.Map:
		// marshaledFields contains the map of JSON field name to marshalled valued
		marshaledFields := map[string]any{}
		iterator := v.MapRange()
		for iterator.Next() {
			key := iterator.Key()
			value := iterator.Value()

			// Constructing the field name

			jsonFieldName, err := stringifyMapKey(key)
			if err != nil {
				return nil, fmt.Errorf("unable to stringify map key of type %T: %w", key.Interface(), err)
			}

			// Marshalling the content

			b, err := marshal(value, typeIDOfer)
			if err != nil {
				return nil, fmt.Errorf("unable to serialize value of map-entry with key '%s': %w", jsonFieldName, err)
			}

			// TODO: deduplicate the code below with the same code in the reflect.Struct case
			// If the field is not interface, then putting the content directly
			if v.Type().Elem().Kind() != reflect.Interface || !reflect.ValueOf(value.Interface()).IsValid() {
				marshaledFields[jsonFieldName] = b
				continue
			}

			// If the field is an interface, then put the value in format: {TypeID: {..Content..}}

			typeID, err := typeIDOfer.TypeIDOf(value.Interface())
			if err != nil {
				return nil, fmt.Errorf("unable to get TypeID of %T: %w", value.Interface(), err)
			}
			marshaledFields[jsonFieldName] = map[TypeID]json.RawMessage{
				typeID: json.RawMessage(b),
			}
		}
		return json.Marshal(marshaledFields)
	case reflect.Slice, reflect.Array:
		// conversion for slices and arrays is not supported, yet
		return json.Marshal(v.Interface())
	case reflect.Struct:
		t := v.Type()

		// marshaledFields contains the map of JSON field name to marshalled valued
		marshaledFields := map[string]any{}

		// Iterating through structure fields:
		for i := 0; i < v.NumField(); i++ {
			fT := t.Field(i)
			fV := v.Field(i)

			if fT.PkgPath != "" {
				// unexported
				continue
			}

			// Detecting the field name

			tag := fT.Tag.Get("json")
			if tag == "-" {
				// requested to skip
				continue
			}
			tagWords := strings.Split(tag, ",")

			jsonFieldName := fT.Name
			if len(tagWords[0]) > 0 {
				jsonFieldName = tagWords[0]
			}

			// Marshalling the content

			b, err := marshal(fV, typeIDOfer)
			if err != nil {
				return nil, fmt.Errorf("unable to serialize data within field #%d:%s of structure %T: %w", i, fT.Name, v.Interface(), err)
			}

			// If the field is not interface or it is an untyped nil, then putting the content directly
			if fT.Type.Kind() != reflect.Interface || !reflect.ValueOf(fV.Interface()).IsValid() {
				marshaledFields[jsonFieldName] = json.RawMessage(b)
				continue
			}

			// If the field is an interface, then put the value in format: {TypeID: {..Content..}}

			typeID, err := typeIDOfer.TypeIDOf(fV.Interface())
			if err != nil {
				return nil, fmt.Errorf("unable to get TypeID of %T: %w", fV.Interface(), err)
			}
			marshaledFields[jsonFieldName] = map[TypeID]json.RawMessage{
				typeID: json.RawMessage(b),
			}
		}

		// Now we get the map of JSON field names to JSONized values. Just compiling this into the final JSON:
		return json.Marshal(marshaledFields)
	}

	// Everything else:
	return json.Marshal(v.Interface())
}

func stringifyMapKey(mapKey reflect.Value) (string, error) {
	if mapKey.Kind() == reflect.String {
		return mapKey.String(), nil
	}

	return "", fmt.Errorf("unable to stringify map key '%#+v' (%T)", mapKey.Interface(), mapKey.Interface())
}

func unstringifyMapKey(mapKey reflect.Value, s string) error {
	if mapKey.Kind() == reflect.String {
		mapKey.SetString(s)
		return nil
	}

	return fmt.Errorf("unable to unstringify map key (%T) value '%s'", mapKey.Interface(), s)
}

// UnmarshalWithTypeIDs is similar to json.Unmarshal, but any interface field
// met in a structure is unserialized as a structure containing the type
// identifier and the value. It allows to unmarshal a JSON (serialized
// by MarshalWithTypeIDs) without loosing typing.
//
// This function is the inverse function for MarshalWithTypeIDs.
//
// NOTE! This is not a drop-in replacement for standard json.Unmarshal.
//
//	It has incompatible behavior.
func UnmarshalWithTypeIDs(b []byte, dst any, newByTypeIDer NewByTypeIDer) error {
	// TODO: use encoding/json.Decoder instead of github.com/tidwall/gjson
	return unmarshal(gjson.ParseBytes(b), reflect.ValueOf(dst), newByTypeIDer)
}

func unmarshal(obj gjson.Result, v reflect.Value, newByTypeIDer NewByTypeIDer) error {
	// How the function works:
	//
	// We are interested only about structures (and their fields),
	// everything else supposed to be handled by standard "encoding/json" package.
	// So we use reflection to go through the value and handle values accordingly.
	//
	// If during iteration through structure fields we meet an interface,
	// we use NewByTypeIDer to create a sample, and then standard "json.Unmarshal" to fill it.

	if v.Kind() != reflect.Pointer {
		return fmt.Errorf("expected a pointer destination, but got %T instead", v.Interface())
	}

	if !v.Elem().IsValid() {
		// Some field may contain a typed nil. But we need to fill the value, so
		// creating an empty value.
		v.Set(reflect.New(v.Type().Elem()))
	}

	switch v.Elem().Kind() {
	case reflect.Interface:
		// unwrapping the interface
		return unmarshal(obj, reflect.ValueOf(v.Interface()), newByTypeIDer)
	case reflect.Pointer:
		return unmarshal(obj, v.Elem(), newByTypeIDer)
	case reflect.Map:
		v = v.Elem()

		// delete all entries from the current map
		iterator := v.MapRange()
		for iterator.Next() {
			v.SetMapIndex(iterator.Key(), reflect.Value{})
		}

		// parse entries to the map
		var err error
		keyType := v.Type().Key()
		valueType := v.Type().Elem()
		// iterating through all entries of the associative array
		obj.ForEach(func(key, value gjson.Result) bool {
			keyValue := reflect.New(keyType).Elem()
			err = unstringifyMapKey(keyValue, key.Str)
			if err != nil {
				err = fmt.Errorf("unable to unstringify key value '%s': %w", key.Str, err)
				return false
			}

			valueValue := reflect.New(valueType).Elem()
			err = unmarshalTo(valueValue, valueType, value, newByTypeIDer)
			if err != nil {
				err = fmt.Errorf("unable to unmarshal JSON '%s' of entry with key '%s': %w", value, key, err)
				return false
			}

			if v.IsNil() {
				// Got a nil map, initializing:
				v.Set(reflect.MakeMap(v.Type()))
			}
			v.SetMapIndex(keyValue, valueValue)
			return true
		})
		return err
	case reflect.Slice, reflect.Array:
		// conversion for slices and arrays is not supported, yet
		return json.Unmarshal([]byte(obj.Raw), v.Interface())
	case reflect.Struct:
		v = v.Elem()
		t := v.Type()

		// indexMap is a map of JSON field name to structure field index (could be used with Field method in reflection)
		indexMap := map[string]int{}
		for i := 0; i < v.NumField(); i++ {
			fT := t.Field(i)

			tag := fT.Tag.Get("json")
			if tag == "-" {
				// requested to skip
				continue
			}
			tagWords := strings.Split(tag, ",")

			jsonFieldName := fT.Name
			if len(tagWords[0]) > 0 {
				jsonFieldName = tagWords[0]
			}

			indexMap[jsonFieldName] = i
		}

		var err error
		// Iterating through fields of the structure provided in the JSON:
		obj.ForEach(func(key, value gjson.Result) bool {
			fieldIndex, ok := indexMap[string(key.Str)]
			if !ok {
				// we have no such field in our struct
				return true
			}

			fT := t.Field(fieldIndex)
			fV := v.Field(fieldIndex)

			if fT.PkgPath != "" {
				// unexported
				return true
			}

			err = unmarshalTo(fV, fT.Type, value, newByTypeIDer)
			if err != nil {
				err = fmt.Errorf("unable to unmarshal JSON '%s' of field '%s': %w", value, key, err)
				return false
			}
			return true
		})
		return err
	}

	// Everything else:
	return json.Unmarshal([]byte(obj.Raw), v.Interface())
}

func unmarshalTo(
	out reflect.Value,
	outType reflect.Type,
	value gjson.Result,
	newByTypeIDer NewByTypeIDer,
) error {
	// By default unmarshaling directly to the field value
	contentOut := out.Addr()

	switch outType.Kind() {
	case reflect.Pointer:
		if value.Type == gjson.Null {
			out.Set(reflect.Zero(outType))
			return nil
		}
	case reflect.Interface:
		// The field is an interface. It is required to generate a value
		// of the type, defined by TypeID and unmarshal the content into it.

		// Checking if it should be the untyped-nil value
		if value.Type == gjson.Null {
			out.Set(reflect.New(outType).Elem())
			return nil
		}

		// Getting the TypeID

		m := value.Map()
		if len(m) != 1 {
			return fmt.Errorf("expected exactly one value, but got %d", len(m))
		}
		var (
			typeID        string
			valueUnparsed gjson.Result
			typedValuePtr any
		)
		// There will be only one value, unpacking it:
		for typeID, valueUnparsed = range m {
		}

		// Generating a value with type correspnding to the TypeID

		typedValuePtr, err := newByTypeIDer.NewByTypeID(TypeID(typeID))
		if err != nil {
			return fmt.Errorf("unable to construct an instance of value for TypeID '%s': %w", typeID, err)
		}

		// Setting to unmarshal the content (JSON) to the generated value

		contentOut = reflect.ValueOf(typedValuePtr)
		value = valueUnparsed
	}

	// unmarshaling the content
	err := unmarshal(value, contentOut, newByTypeIDer)
	if err != nil {
		return fmt.Errorf("unable to unmarshal: %w", err)
	}

	if outType.Kind() == reflect.Interface {
		// Since it was an interface and we generated a dedicated variable to unmarshal to,
		// no we need to set the final value to the structure field.

		// There are few cases possible:
		switch {
		case contentOut.Elem().Type().AssignableTo(outType):
			// This is the main case. Here we just set the resulting
			// value the the field.
			out.Set(contentOut.Elem())
		case contentOut.Type().AssignableTo(outType):
			// Some TypeID handlers may dereference pointers, and
			// because of this we need to get back to references,
			// so we remove "Elem()"
			out.Set(contentOut)
		default:
			return fmt.Errorf("internal error: do not know how to assign %T to %s", contentOut.Elem(), outType)
		}
	}

	return nil
}

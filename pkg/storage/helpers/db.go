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
	"database/sql"
	"database/sql/driver"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/stoewer/go-strcase"
)

func columnNameFromFieldName(fieldName string) string {
	return strcase.SnakeCase(fieldName)
}

// GetDBColumnName returns column name from sql tag string
func GetDBColumnName(t reflect.Type, fieldName string) (string, error) {
	f, ok := t.FieldByName(fieldName)
	if !ok {
		return "", fmt.Errorf("field '%s' is not found", fieldName)
	}
	value, found := f.Tag.Lookup("db")
	if !found {
		return columnNameFromFieldName(fieldName), nil
	}
	idx := strings.Index(value, ",")
	if idx == -1 {
		return value, nil
	}
	return value[0:idx], nil
}

// GetValuesAndColumns parses input's structure values and appropriate sql columns
func GetValuesAndColumns(obj any, shouldSkip func(fieldName string, value any) bool) ([]any, []string, error) {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer && !v.Elem().IsValid() {
		// the provided sample is a typed-nil, creating a non-nil value to avoid a panic in getValuesAndColumns
		v = reflect.New(v.Type().Elem())
	}
	return getValuesAndColumns("", reflect.Indirect(v), shouldSkip)
}

func getValuesAndColumns(prefix string, e reflect.Value, shouldSkip func(fieldName string, value any) bool) ([]any, []string, error) {
	t := e.Type()

	var columns []string
	var values []any
	for i := 0; i < e.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			// not exported
			continue
		}
		if shouldSkip != nil {
			if skip := shouldSkip(f.Name, e.Field(i).Interface()); skip {
				continue
			}
		}

		columnName, err := GetDBColumnName(t, f.Name)
		if err != nil {
			return nil, nil, err
		}

		if columnName == "-" {
			// column name "-" means the field is not stored in the database, thus
			// skipping it here.
			continue
		}

		v := e.Field(i)
		// Some structures have special support by `sql` packages and we do not need to decompose them to
		// separate fields. Moreover, for example `time.Time` has no public fields, thus to store the
		// value to SQL correctly we need to leave the structure as is (instead of iterating through fields).
		switch v.Interface().(type) {
		case sql.NullBool, sql.NullByte, sql.NullFloat64, sql.NullInt16, sql.NullInt32, sql.NullInt64, sql.NullString, sql.NullTime, time.Time:
			// TODO: try to remove sql.* cases from here, since they should be covered by `f.Type.Implements` below.
			columns = append(columns, columnName)
			if v.CanAddr() {
				v = v.Addr()
			}
			values = append(values, v.Interface())
			continue
		}

		switch v := reflect.Indirect(v); v.Kind() {
		case reflect.Struct:
			if f.Type.Implements(reflect.ValueOf((*driver.Valuer)(nil)).Type().Elem()) {
				// it is an SQL value, no need to decompose it to fields.
				break
			}
			if !v.IsValid() {
				v = reflect.New(f.Type.Elem()).Elem() // using zero value
			}

			// Recursive walk to the nested structures
			//
			// In result we flatten-out the sub-structures.
			childPrefix := prefix
			if !f.Anonymous {
				childPrefix += columnName + "_"
			}
			childValues, childColumns, err := getValuesAndColumns(childPrefix, v, shouldSkip)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to process field '%s': %w", f.Name, err)
			}
			values = append(values, childValues...)
			columns = append(columns, childColumns...)
			continue
		}

		columns = append(columns, columnName)
		if v.CanAddr() {
			v = v.Addr()
		}
		values = append(values, v.Interface())
	}

	return values, columns, nil
}

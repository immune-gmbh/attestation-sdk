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

	values, columns, err := GetValuesAndColumns(d, func(fieldName string, value interface{}) bool {
		return fieldName == "Registers"
	})
	require.NoError(t, err)
	require.Len(t, values, len(columns))

	require.Equal(t, ptr(uint64(42)), values[0])
	require.Equal(t, "id", columns[0])

	require.Equal(t, ptr(true), values[1])
	require.Equal(t, "unknown", columns[1])
}

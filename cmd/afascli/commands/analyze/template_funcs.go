package analyze

import (
	"fmt"
	"reflect"
	"text/template"

	"github.com/google/uuid"
)

var templateFuncs = template.FuncMap{
	"first": func(in any) any {
		v := reflect.ValueOf(in)
		return v.Index(0).Interface()
	},
	"asUUID": func(in any) string {
		var (
			u   uuid.UUID
			err error
		)
		switch in := in.(type) {
		case []byte:
			if len(in) == 16 {
				copy(u[:], in)
			} else {
				u, err = uuid.ParseBytes(in)
			}
		case string:
			u, err = uuid.Parse(in)
		default:
			panic(fmt.Errorf("unexpected type: %T", in))
		}
		if err != nil {
			panic(err)
		}
		return u.String()
	},
}

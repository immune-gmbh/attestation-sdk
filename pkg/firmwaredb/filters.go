package rtpdb

import (
	"strings"
)

// Filters is a set of Filter (logically joined through "AND").
type Filters []Filter

// WhereCond implements Filter.
func (f Filters) WhereCond() (string, []interface{}) {
	return f.joinWhereConds("AND")
}

func (f Filters) joinWhereConds(joinOp string) (string, []interface{}) {
	if len(f) == 0 {
		return "1 = 1", nil
	}

	var whereConds []string
	var args []interface{}
	for _, filter := range f {
		localWhere, localArgs := filter.WhereCond()
		whereConds = append(whereConds, localWhere)
		args = append(args, localArgs...)
	}

	return "(" + strings.Join(whereConds, ") "+joinOp+" (") + ")", args
}

// Match implements Filter.
func (f Filters) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, filter := range f {
		if !filter.Match(fw) {
			return false
		}
	}
	return true
}

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

package firmwaredb

import (
	"strings"
)

// Filters is a set of Filter (logically joined through "AND").
type Filters []Filter

// WhereCond implements Filter.
func (f Filters) WhereCond() (string, []any) {
	return f.joinWhereConds("AND")
}

func (f Filters) joinWhereConds(joinOp string) (string, []any) {
	if len(f) == 0 {
		return "1 = 1", nil
	}

	var whereConds []string
	var args []any
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

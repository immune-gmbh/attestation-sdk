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

package display_eventlog

import (
	"flag"
	"fmt"
	"strings"
)

var _ flag.Value = (*flagFormat)(nil)

type flagFormat uint

const (
	flagFormatPlaintextOneline = flagFormat(iota)
	flagFormatPlaintextMultiline
	endOfFlagFormat
)

// String implements flag.Value.
func (f flagFormat) String() string {
	switch f {
	case flagFormatPlaintextOneline:
		return "plaintext-oneline"
	case flagFormatPlaintextMultiline:
		return "plaintext-multiline"
	}
	return fmt.Sprintf("unknown_format_%d", f)
}

// Set implements flag.Value.
func (f *flagFormat) Set(in string) error {
	in = strings.Trim(strings.ToLower(in), " ")
	for v := flagFormat(0); v < endOfFlagFormat; v++ {
		if in == v.String() {
			*f = v
			return nil
		}
	}
	return fmt.Errorf("unknown format '%s'", in)
}

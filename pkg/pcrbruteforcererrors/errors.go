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
package pcrbruteforcererrors

import (
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcrbruteforcer"
)

// ErrReproduceEventLogIssues returns issues (not really errors) observed,
// while an attempt to reproduce TPM EventLog.
//
// See github.com/9elements/converged-security-suite/v2/pkg/pcrbruteforcer.ReproduceEventLog
type ErrReproduceEventLogIssues struct {
	Issues []pcrbruteforcer.Issue
}

var _ pcrbruteforcer.Issue = (*ErrReproduceEventLogIssues)(nil)
var _ error = (*ErrReproduceEventLogIssues)(nil)

func (e ErrReproduceEventLogIssues) Error() string {
	if len(e.Issues) == 1 {
		return e.Issues[0].Error()
	}
	var result strings.Builder
	result.WriteString(fmt.Sprintf("there are %d issues reported by EventLog reproducer:\n", len(e.Issues)))
	for idx, issue := range e.Issues {
		result.WriteString(fmt.Sprintf("\t%d. %s\n", idx+1, issue.Error()))
	}
	return result.String()
}

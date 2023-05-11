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
package observability

import (
	"os"
	"os/user"
	"strings"

	"github.com/facebookincubator/go-belt/pkg/field"
)

// DefaultFields returns default structured data for observability tooling (logging, tracing, etc)
func DefaultFields() field.Fields {
	var result field.Fields

	result = append(result, field.Field{
		Key:   "pid",
		Value: FieldPID(os.Getpid()),
	})
	result = append(result, field.Field{
		Key:   "uid",
		Value: FieldUID(os.Getuid()),
	})
	if curUser, _ := user.Current(); curUser != nil {
		result = append(result, field.Field{
			Key:   "username",
			Value: FieldUsername(curUser.Name),
		})
	}
	if hostname, err := os.Hostname(); err == nil {
		result = append(result, field.Field{
			Key:   "hostname",
			Value: FieldHostname(hostname),
		})
	}
	if s := os.Getenv("SMC_TIERS"); s != "" {
		result = append(result, field.Field{
			Key:   "smcTiers",
			Value: FieldSMCTiers(strings.Split(s, ",")),
		})
	}
	for keySrc, keyDst := range map[string]string{
		"TW_JOB_CLUSTER": "twJobCluster",
		"TW_JOB_USER":    "twJobUser",
		"TW_JOB_NAME":    "twJobName",
		"TW_TASK_ID":     "twTaskID",
	} {
		if s := os.Getenv(keySrc); s != "" {
			result = append(result, field.Field{
				Key:   keyDst,
				Value: s,
			})
		}
	}

	return result
}

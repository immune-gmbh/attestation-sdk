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
package logentryfingerprint

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/facebookincubator/go-belt"
	"github.com/facebookincubator/go-belt/pkg/field"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/types"
)

// FieldValue is the custom type for a field, which
// contains the resulting signature/fingerprint.
type FieldValue string

// PreHook generates so-so stable unique signatures/fingerprint (basically just hashes)
// for each place where we issue logs through a Logger.
//
// The term "signature" here is not in cryptographic meaning, but in
// algorithmic: https://en.wikipedia.org/wiki/Signature_(logic)
//
// This is a semantic analogy of the default implementation of a fingerprint like in Sentry:
//
//	https://docs.sentry.io/product/sentry-basics/grouping-and-fingerprints/
//
// The parts expected to be variable are ignored, such as TraceIDs and format arguments.
//
// It could be used to automatically categorize errors, for example.
//
// To override the algorithm of the fingerprint, just set another hook.
type PreHook struct{}

var _ logger.PreHook = PreHook{}

const (
	// FieldKey is the key value of field, which contains
	// the log entry signature/fingerprint (see also FieldValue).
	FieldKey = "immune/logentryfingerprint"
)

func newLogEntryFingerprintResult(
	level logger.Level,
	staticMessage string,
	fields field.AbstractFields,
	customArgs []any,
) types.PreHookResult {
	// TODO: optimize this
	h := sha1.New() // we do not expect a cryptographic hash, just expect not to collide hash values unintentionally
	h.Write([]byte(fmt.Sprintf("%s-%s", level, staticMessage)))
	for _, arg := range customArgs {
		h.Write([]byte{0}) // separator
		h.Write([]byte(reflect.ValueOf(arg).Type().Name()))
	}
	if fields != nil {
		fields.ForEachField(func(f *field.Field) bool {
			h.Write([]byte{0}) // separator
			h.Write([]byte(f.Key))
			return true
		})
	}

	return types.PreHookResult{
		ExtraFields: &field.Field{
			Key:   FieldKey,
			Value: FieldValue(hex.EncodeToString(h.Sum(nil))),
		},
	}
}

// ProcessInput implements logger.PreHook (see the description of the `PreHook` structure)
func (PreHook) ProcessInput(_ belt.TraceIDs, level logger.Level, args ...any) types.PreHookResult {
	return newLogEntryFingerprintResult(level, "", nil, args)
}

// ProcessInputf implements logger.PreHook (see the description of the `PreHook` structure)
func (PreHook) ProcessInputf(_ belt.TraceIDs, level logger.Level, format string, _ ...any) types.PreHookResult {
	return newLogEntryFingerprintResult(level, format, nil, nil)
}

// ProcessInputFields implements logger.PreHook (see the description of the `PreHook` structure)
func (PreHook) ProcessInputFields(_ belt.TraceIDs, level logger.Level, message string, fields field.AbstractFields) types.PreHookResult {
	return newLogEntryFingerprintResult(level, message, fields, nil)
}

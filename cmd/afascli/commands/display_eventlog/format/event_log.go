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

package format

import (
	"fmt"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// PCRIndexPtr is just a replacement for ugly &[]pcr.ID{in}[0]
func PCRIndexPtr(in pcr.ID) *pcr.ID {
	return &in
}

// HashAlgoPtr is just a replacement for ugly &[]tpmeventlog.TPMAlgorithm{in}[0]
func HashAlgoPtr(in tpmeventlog.TPMAlgorithm) *tpmeventlog.TPMAlgorithm {
	return &in
}

// EventLog returns a string with a formatted TPM EventLog.
func EventLog(
	eventLog *tpmeventlog.TPMEventLog,
	filterPCRIndex *pcr.ID,
	filterHashAlgo *tpmeventlog.TPMAlgorithm,
	prefix string,
	isMultiline bool,
) string {
	var result strings.Builder

	if !isMultiline {
		result.WriteString(fmt.Sprintf("%s  #\tidx\t      type\thash\tdigest\tdata\n", prefix))
	}
	for idx, ev := range eventLog.Events {
		if filterPCRIndex != nil && *filterPCRIndex != ev.PCRIndex {
			continue
		}

		var hash tpmeventlog.TPMAlgorithm
		var digest []byte
		if ev.Digest != nil {
			hash = ev.Digest.HashAlgo
			digest = ev.Digest.Digest
		}
		if filterHashAlgo != nil && (ev.Digest == nil || hash != *filterHashAlgo) {
			continue
		}

		if isMultiline {
			writeField := func(fieldName, valueFormat string, value any) {
				result.WriteString(fmt.Sprintf("%s%-20s: "+valueFormat+"\n", prefix, fieldName, value))
			}
			writeField("#", "%d", idx)
			writeField("PCR index", "%d", ev.PCRIndex)
			writeField("Event Type", "%d", ev.Type)
			writeField("Hash Algorithm", "%d", hash)
			writeField("Digest", "%X", digest)
			dataDump := (&spew.ConfigState{Indent: prefix + "    > "}).Sdump(ev.Data)
			writeField("Data", "%s", dataDump)
		} else {
			result.WriteString(fmt.Sprintf("%s%3d\t%2d\t%10d\t%3d\t%X\t%X\n", prefix, idx, ev.PCRIndex, ev.Type, hash, digest, ev.Data))
		}
	}

	return result.String()
}

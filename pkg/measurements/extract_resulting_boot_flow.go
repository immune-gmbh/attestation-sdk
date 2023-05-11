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
package measurements

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/flowscompat"
)

// ExtractResultingBootFlow returns the simplest bootflow, which results into
// equivalent of what happened according to the log.
//
// TODO: delete this, this is an intermediate code while migrating from `pcr` to `bootflow`:
func ExtractResultingBootFlow(log bootengine.Log) bootflowtypes.Flow {
	// Here we just look for the last jump which leads to a bootflow
	// known by ToOld. While ToOld represents only those bootflows
	// which are of interest to the end user.
	for idx := len(log) - 1; idx >= 0; idx-- {
		stepResult := log[idx]
		for _, action := range stepResult.Actions {
			switch setFlow := action.(type) {
			case *commonactions.SetFlowStruct:
				r := flowscompat.ToOld(setFlow.NextFlow)
				if r != pcr.FlowAuto && r != pcr.Flow(-1) {
					return setFlow.NextFlow
				}
			}
		}
	}

	return flows.Root
}

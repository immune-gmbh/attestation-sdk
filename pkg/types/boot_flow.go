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
package types

import (
	"encoding/json"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

// BootFlow is a wrapper for types.Flow to make it serializable/deserializable using xjson.
type BootFlow types.Flow

// MarshalJSON implements json.Marshaler.
func (flow BootFlow) MarshalJSON() ([]byte, error) {
	return json.Marshal(flow.Name)
}

// UnmarshalJSON implements json.Unmarshaler.
func (flow *BootFlow) UnmarshalJSON(b []byte) error {
	var flowName string
	err := json.Unmarshal(b, &flowName)
	if err != nil {
		return fmt.Errorf("unable to un-JSON-ize the flow name '%s': %w", b, err)
	}
	v, found := getFlowByName(flowName)
	if !found {
		return fmt.Errorf("flow '%s' is not found", flowName)
	}

	*flow = BootFlow(v)
	return nil
}

func getFlowByName(flowName string) (types.Flow, bool) {
	switch flowName {
	case flows.Root.Name:
		return flows.Root, true
	case flows.AMD.Name:
		return flows.AMD, true
	case flows.AMDGenoa.Name:
		return flows.AMDGenoa, true
	case flows.AMDGenoaLocality0.Name:
		return flows.AMDGenoaLocality0, true
	case flows.AMDGenoaLocality3.Name:
		return flows.AMDGenoaLocality3, true
	case flows.AMDGenoaLocality0V2.Name:
		return flows.AMDGenoaLocality0V2, true
	case flows.AMDGenoaLocality3V2.Name:
		return flows.AMDGenoaLocality3V2, true
	case flows.AMDGenoaVerificationFailure.Name:
		return flows.AMDGenoaVerificationFailure, true
	case flows.AMDGenoaVerificationFailureV2.Name:
		return flows.AMDGenoaVerificationFailureV2, true
	case flows.Intel.Name:
		return flows.Intel, true
	case flows.IntelCBnT.Name:
		return flows.IntelCBnT, true
	case flows.IntelCBnTFailure.Name:
		return flows.IntelCBnTFailure, true
	case flows.IntelLegacyTXTEnabled.Name:
		return flows.IntelLegacyTXTEnabled, true
	case flows.IntelLegacyTXTEnabledTPM12.Name:
		return flows.IntelLegacyTXTEnabledTPM12, true
	case flows.IntelLegacyTXTDisabled.Name:
		return flows.IntelLegacyTXTDisabled, true
	case flows.PEI.Name:
		return flows.PEI, true
	case flows.OCPPEI.Name:
		return flows.OCPPEI, true
	case flows.DXE.Name:
		return flows.DXE, true
	}
	return types.Flow{}, false
}

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
	case flows.IntelLegacyTXT.Name:
		return flows.IntelLegacyTXT, true
	case flows.PEI.Name:
		return flows.PEI, true
	case flows.OCPPEI.Name:
		return flows.OCPPEI, true
	case flows.DXE.Name:
		return flows.DXE, true
	}
	return types.Flow{}, false
}

// TODO: delete this package

package flowscompat

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
)

// FromOld converts the flow from old package `pcr` to new package `bootflow`.
//
// This is the reverse function of ToOld.
func FromOld(old pcr.Flow) types.Flow {
	switch old {
	case pcr.FlowAuto:
		return flows.Root
	case pcr.FlowIntelLegacyTXTDisabled:
		return flows.IntelLegacyTXTDisabled
	case pcr.FlowIntelLegacyTXTEnabledTPM12:
		return flows.IntelLegacyTXTEnabledTPM12
	case pcr.FlowIntelLegacyTXTEnabled:
		return flows.IntelLegacyTXTEnabled
	case pcr.FlowIntelCBnT0T:
		return flows.IntelCBnT
	case pcr.FlowAMDLocality0:
		return flows.AMDMilanLocality0
	case pcr.FlowAMDLocality3:
		return flows.AMDMilanLocality3
	}

	errDesc := fmt.Sprintf("unknown flow '%s'", old.String())
	return types.Flow{
		Name: errDesc,
		Steps: types.Steps{
			commonsteps.Panic(errDesc),
		},
	}
}

// ToOld converts the flow from new package `bootflow` to old package `pcr`.
//
// This is the reverse function of FromOld.
func ToOld(new types.Flow) pcr.Flow {
	switch new.Name {
	case flows.Root.Name:
		return pcr.FlowAuto
	case flows.IntelLegacyTXTEnabled.Name:
		return pcr.FlowIntelLegacyTXTEnabled
	case flows.IntelLegacyTXTDisabled.Name:
		return pcr.FlowIntelLegacyTXTDisabled
	case flows.IntelLegacyTXTEnabledTPM12.Name:
		return pcr.FlowIntelLegacyTXTEnabledTPM12
	case flows.IntelCBnT.Name:
		return pcr.FlowIntelCBnT0T
	case flows.AMDMilanLocality0.Name:
		return pcr.FlowAMDLocality0
	case flows.AMDMilanLocality3.Name:
		return pcr.FlowAMDLocality3
	}

	return pcr.Flow(-1)
}

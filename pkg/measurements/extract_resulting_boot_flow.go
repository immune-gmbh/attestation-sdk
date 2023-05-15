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

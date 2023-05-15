package controller

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/device"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/identity"
)

// ExtractHostnameFromCtx extracts hostname from provided thrift context
func ExtractHostnameFromCtx(ctx context.Context) (hostname string, isVerified bool) {
	clientIdentities, err := identity.NewIdentitiesFromContext(ctx)
	if err != nil {
		return "", false
	}

	for _, clientIdentity := range clientIdentities {
		hostname = clientIdentity.TLSChain()[0].DNSNames[0]
	}

	// set isVerified to true if TLSChain is valid
	return
}

func enrichHostInfo(ctx context.Context, device *device.Device, isVerified bool, hostInfo *afas.HostInfo) {
	if device != nil {
		hostInfo.IsVerified = isVerified
		if isVerified || device.Hostname != nil {
			hostInfo.Hostname = device.Hostname
		}
		hostInfo.AssetID = &[]int64{device.AssetID}[0]
		hostInfo.ModelID = &device.ModelID
	}

	if hostInfo.AssetID == nil {
		hostname := "<nil>"
		if hostInfo.Hostname != nil {
			hostname = *hostInfo.Hostname
		}
		logger.FromCtx(ctx).Warnf("AssetID is nil. Hostname: '%v'", hostname)
	}
}

package controller

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"facebook/core_systems/server/device"
	"facebook/infrasec/authorization/acl"
	"libfb/go/identity"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/rtp"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/typeconv"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/rtpfw"
	"thrift/lib/go/thrift"
)

// ExtractHostnameFromCtx extracts hostname from provided thrift context
func ExtractHostnameFromCtx(ctx context.Context) (hostname string, isVerified bool) {
	clientIdentities, err := identity.NewIdentitiesFromContext(ctx)
	if err != nil {
		return "", false
	}

	for _, clientIdentity := range clientIdentities {
		if clientIdentity.GetIdType() == acl.MACHINE {
			hostname = clientIdentity.GetIdData()
			break
		}
	}

	cinfo, ok := thrift.ConnInfoFromContext(ctx)
	if !ok {
		return
	}

	isVerified = len(cinfo.TLS().VerifiedChains) > 0
	return
}

func getClientSeRFDevice(
	ctx context.Context,
	serf serfInterface,
	hostInfo *afas.HostInfo,
) (dev *device.Device, isVerified bool) {
	if hostInfo == nil {
		return nil, false
	}
	log := logger.FromCtx(ctx)

	clientHostname, isVerifiedClientHostname := ExtractHostnameFromCtx(ctx)
	log.Debugf("detected TLS identity hostname: %s (isVerified: %v)", clientHostname, isVerifiedClientHostname)
	if hostInfo.GetHostname() == clientHostname {
		// attest proxy may send an Analyze request on behalf of another target
		// so we can use the TLS certificate to verify the hostname,
		// only of client hostname matches the hostname in hostInfo
		isVerified = isVerifiedClientHostname
	}

	var err error
	if hostInfo.AssetID != nil {
		dev, err = serf.GetDeviceById(*hostInfo.AssetID)
		if err == nil {
			return
		}
		log.Warnf("failed to get SeRF info by asset id %d: %v", *hostInfo.AssetID, err)
	}

	if hostInfo.Hostname != nil {
		dev, err = serf.GetDeviceByName(*hostInfo.Hostname)
		if err == nil {
			return
		}
		log.Warnf("failed to get SeRF info for %s: %v", *hostInfo.Hostname, err)
	}

	return
}

func enrichHostInfo(ctx context.Context, serfDevice *device.Device, isVerified bool, hostInfo *afas.HostInfo) {
	if serfDevice != nil {
		hostInfo.IsVerified = isVerified
		if isVerified || serfDevice.Name != nil {
			hostInfo.Hostname = serfDevice.Name
		}
		hostInfo.AssetID = &[]int64{int64(serfDevice.Id)}[0]
		hostInfo.ModelID = &serfDevice.ModelID
	}

	if hostInfo.AssetID == nil {
		hostname := "<nil>"
		if hostInfo.Hostname != nil {
			hostname = *hostInfo.Hostname
		}
		logger.FromCtx(ctx).Warnf("AssetID is nil. Hostname: '%v'", hostname)
	}
}

func getRTPEvaluationStatus(ctx context.Context, serfDevice *device.Device) rtp.EvaluationStatus {
	evaluationStatus := rtpfw.EvaluationStatusMostProductionReady
	log := logger.FromCtx(ctx)
	if serfDevice != nil {
		if v, err := typeconv.FromSERFToThriftEvaluationStatus(serfDevice.EvaluationStatus); err != nil {
			log.Errorf("Failed to convert evaluation status: %v", err)
		} else {
			evaluationStatus = v
		}
	}
	log.Infof("Evaluation status: '%s'", evaluationStatus)
	return evaluationStatus
}

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
package controller

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/attestation-sdk/if/generated/afas"
	"github.com/immune-gmbh/attestation-sdk/if/generated/device"
	"github.com/immune-gmbh/attestation-sdk/pkg/identity"
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

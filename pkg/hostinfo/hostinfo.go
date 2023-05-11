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
package hostinfo

import (
	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
)

const (
	// maximal object size in SMBIOS is 64KiB ("Maximum Structure Size" is
	// defined in bytes by a WORD).
	maxLengthSerialNumber = 65536
	// according to RFC1035, a name length limit is 255 octets.
	maxLengthFQDN = 255
)

// FixHostInfo checks and fixes HostInfo for data we require
func FixHostInfo(hostInfo *afas.HostInfo, logger logger.Logger) {
	if hostInfo.SerialNumber != nil && len(*hostInfo.SerialNumber) > maxLengthSerialNumber {
		logger.Errorf("too big serial number (len:%d)", len(*hostInfo.SerialNumber))
		hostInfo.SerialNumber = nil
	}
	if hostInfo.Hostname != nil && len(*hostInfo.Hostname) > maxLengthFQDN {
		logger.Errorf("too big hostname (len:%d)", len(*hostInfo.Hostname))
		hostInfo.Hostname = nil
	}
}

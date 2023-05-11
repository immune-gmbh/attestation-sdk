package hostinfo

import (
	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/afas"
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

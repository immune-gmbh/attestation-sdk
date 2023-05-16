package firmwarewand

import (
	"os"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/dmidecode"
)

func localHostInfo() (*afas.HostInfo, error) {
	var hostInfo afas.HostInfo
	hostInfo.IsClientHostAnalyzed = true

	hostname, err := os.Hostname()
	if err != nil {
		return nil, ErrDetectHostname{Err: err}
	}
	hostInfo.Hostname = &hostname

	dmiTable, _ := dmidecode.LocalDMITable()
	if dmiTable != nil {
		sn := dmiTable.SystemInfo().SystemSerialNumber
		hostInfo.SerialNumber = &sn
	}

	return &hostInfo, nil
}

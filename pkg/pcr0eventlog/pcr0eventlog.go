package pcr0eventlog

import (
	tpmeventlog "github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
)

const (
	// we expect that PCR0 measurements will require only about 5 events,
	// and only one of them could be large (about 1KiB), thus 10KiB should
	// be more than enough.
	maxSizeEventData = 10 * 1024
)

// CheckTPMEventLog checks the TPM Event Log
func CheckTPMEventLog(eventLog *tpmeventlog.TPMEventLog, logger logger.Logger) {
	eventLogSizePCR0 := uint(0)
	var filteredEventsPCR0 []*tpmeventlog.Event
	for _, event := range eventLog.Events {
		if event.PCRIndex != 0 {
			continue
		}
		if event.Digest == nil {
			logger.Errorf("event.Digest == nil")
			continue
		}

		hash, err := event.Digest.HashAlgo.Hash()
		if err != nil {
			logger.Errorf("unexpected hash algorithm: %v", event.Digest.HashAlgo)
			continue
		}

		hasher := hash.HashFunc()

		digestSize := uint(hasher.Size())
		if uint(len(event.Digest.Digest)) != digestSize {
			logger.Errorf("unexpected size of %v digest: %v", event.Digest.HashAlgo, len(event.Digest.Digest))
			continue
		}

		// minimalSerializedEventInScuba is the minimal representation of an EventLog entry in the Scuba field.
		// EventLog is being serialized to JSON (see also package scubareport).
		minimalSerializedEventInScuba := `{"Index":0,"Type":0,"Digest":{"PCRBank":0,"Digest":""},"Data":""}`

		size := uint(len(event.Digest.Digest)) + uint(len(event.Data)) + uint(len(minimalSerializedEventInScuba))

		filteredEventsPCR0 = append(filteredEventsPCR0, event)
		eventLogSizePCR0 += size
	}
	if eventLogSizePCR0 < maxSizeEventData {
		eventLog.Events = filteredEventsPCR0
	} else {
		logger.Errorf("EventLog is too large (size:%d)", eventLogSizePCR0)
		eventLog.Events = nil
	}

	logger.Debugf("filtered EventLog is %v", *eventLog)
}

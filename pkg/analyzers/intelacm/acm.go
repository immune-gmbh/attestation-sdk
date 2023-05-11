package intelacm

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm/report/generated/intelacmanalysis"
)

// GetACMInfo tries to parse ACM information from a firmware image
func GetACMInfo(image []byte) (*intelacmanalysis.ACMInfo, error) {
	entries, err := fit.GetEntries(image)
	if err != nil {
		return nil, ErrParsingFITEntries{err: err}
	}

	acmInfo, _, err := findACM(entries)
	if err != nil {
		return nil, err
	}

	result := &intelacmanalysis.ACMInfo{
		Date:   int32(acmInfo.GetDate()),
		SESVN:  int16(acmInfo.GetSESVN()),
		TXTSVN: int16(acmInfo.GetTXTSVN()),
	}

	// Signature verification is blocked by:
	// https://premiersupport.intel.com/IPS/5003b00001cnlpi
	//result.SignatureIsValid = acmInfo.VerifySignature()
	return result, err
}

func findACM(fitEntries []fit.Entry) (*fit.EntrySACMData, *fit.EntrySACM, error) {
	for _, fitEntry := range fitEntries {
		switch fitEntry := fitEntry.(type) {
		case *fit.EntrySACM:
			acmData, err := fitEntry.ParseData()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse ACM, err: %v", err)
			}
			return acmData, fitEntry, nil
		}
	}
	return nil, nil, &ErrNoSACMFound{}
}

// ErrParsingFITEntries means that an error happened when trying to get FIT entries
type ErrParsingFITEntries struct {
	err error
}

func (e ErrParsingFITEntries) Error() string {
	return fmt.Sprintf("failed to parse FIT entries: %v", e.err)
}

// ErrNoSACMFound means that "Startup AC Module" entry was not found
type ErrNoSACMFound struct{}

func (e ErrNoSACMFound) Error() string {
	return "Startup AC Module entry is not found in FIT"
}

package intelacm

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm/report/intelacmanalysis"

	"github.com/facebookincubator/go-belt/tool/logger"
)

func init() {
	analysis.RegisterType((*intelacmanalysis.IntelACMDiagInfo)(nil))
}

// ID represents the unique id of DiffMeasuredBoot analyzer
const ID analysis.AnalyzerID = intelacmanalysis.IntelACMAnalyzerID

// NewExecutorInput builds an analysis.Executor's input required for IntelACM analyzer
func NewExecutorInput(
	originalFirmware analysis.Blob,
	actualFirmware analysis.Blob,
) (analysis.Input, error) {
	if originalFirmware == nil || actualFirmware == nil {
		return nil, fmt.Errorf("firmware images should be specified (got: orig: %v; actual: %v)", originalFirmware, actualFirmware)
	}

	result := analysis.NewInput()
	result.AddOriginalFirmware(
		originalFirmware,
	).AddActualFirmware(
		actualFirmware,
	)
	return result, nil
}

// Input is an input structure required for analyzer
type Input struct {
	OriginalFirmware analysis.OriginalFirmwareBlob
	ActualFirmware   analysis.ActualFirmwareBlob
}

// IntelACM is analyzer that tries to reproduce given PCR0 value
type IntelACM struct{}

// New returns a new object of IntelACM analyzer
func New() analysis.Analyzer[Input] {
	return &IntelACM{}
}

// ID implements the ID method required for analysis.Analyzer
func (analyzer *IntelACM) ID() analysis.AnalyzerID {
	return ID
}

// Analyze makes the ACM gathering
func (analyzer *IntelACM) Analyze(ctx context.Context, in Input) (*analysis.Report, error) {
	var wg sync.WaitGroup

	var originalACM *intelacmanalysis.ACMInfo
	var errOriginal error
	wg.Add(1)
	go func() {
		defer wg.Done()

		originalACM, errOriginal = GetACMInfo(in.OriginalFirmware.Bytes())
	}()

	var receivedACM *intelacmanalysis.ACMInfo
	var errReceived error
	wg.Add(1)
	go func() {
		defer wg.Done()

		receivedACM, errReceived = GetACMInfo(in.ActualFirmware.Bytes())
	}()
	wg.Wait()

	if errors.As(errOriginal, &ErrParsingFITEntries{}) {
		logger.FromCtx(ctx).Infof("Non-Intel firmware, skip analysis")
		return nil, analysis.NewErrNotApplicable("non-intel firmware")
	}

	result := &analysis.Report{
		Custom: intelacmanalysis.IntelACMDiagInfo{
			Original: originalACM,
			Received: receivedACM,
		},
	}

	for _, err := range []error{errOriginal, errReceived} {
		if err != nil {
			result.Issues = append(result.Issues, analysis.Issue{
				Severity:    analysis.SeverityWarning,
				Description: err.Error(),
			})
		}
	}

	if errOriginal == nil && errReceived == nil {
		if !reflect.DeepEqual(originalACM, receivedACM) {
			// TODO: use internal types instead of thrift ones, and define GoString() instead of `formatACM`.
			result.Issues = append(result.Issues, analysis.Issue{
				Severity:    analysis.SeverityCritical,
				Description: fmt.Sprintf("Different ACM info. Original: '%s', actual: '%s'", formatACM(originalACM), formatACM(receivedACM)),
			})
		}
	}
	return result, nil
}

func formatACM(acm *intelacmanalysis.ACMInfo) string {
	return fmt.Sprintf(`{Date:0x%08X, SESVN:%d, TXTSVN:%d}`, acm.Date, acm.SESVN, acm.TXTSVN)
}

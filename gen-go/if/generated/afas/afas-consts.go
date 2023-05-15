// Code generated by Thrift Compiler (0.14.0). DO NOT EDIT.

package afas

import (
	"bytes"
	"context"
	"fmt"
	"github.com/apache/thrift/lib/go/thrift"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/analyzerreport"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/caching_policy"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/measurements"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/tpm"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/diffmeasuredboot/report/generated/diffanalysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analyzers/intelacm/report/generated/intelacmanalysis"
	"time"
)

// (needed to ensure safety because of naive import list construction.)
var _ = thrift.ZERO
var _ = fmt.Printf
var _ = context.Background
var _ = time.Now
var _ = bytes.Equal

var _ = analyzerreport.GoUnusedProtection__
var _ = caching_policy.GoUnusedProtection__
var _ = measurements.GoUnusedProtection__
var _ = tpm.GoUnusedProtection__
var _ = diffanalysis.GoUnusedProtection__
var _ = intelacmanalysis.GoUnusedProtection__

func init() {
}

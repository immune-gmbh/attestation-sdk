package pcrbruteforcererrors

import (
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcrbruteforcer"
)

// ErrReproduceEventLogIssues returns issues (not really errors) observed,
// while an attempt to reproduce TPM EventLog.
//
// See github.com/9elements/converged-security-suite/v2/pkg/pcrbruteforcer.ReproduceEventLog
type ErrReproduceEventLogIssues struct {
	Issues []pcrbruteforcer.Issue
}

var _ pcrbruteforcer.Issue = (*ErrReproduceEventLogIssues)(nil)
var _ error = (*ErrReproduceEventLogIssues)(nil)

func (e ErrReproduceEventLogIssues) Error() string {
	if len(e.Issues) == 1 {
		return e.Issues[0].Error()
	}
	var result strings.Builder
	result.WriteString(fmt.Sprintf("there are %d issues reported by EventLog reproducer:\n", len(e.Issues)))
	for idx, issue := range e.Issues {
		result.WriteString(fmt.Sprintf("\t%d. %s\n", idx+1, issue.Error()))
	}
	return result.String()
}

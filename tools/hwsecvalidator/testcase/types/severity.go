package types

type Severity uint

const (
	// SeverityUndefined is just the zero-value of Severity.
	SeverityUndefined = Severity(iota)

	// SeverityInfo means a failed test should not be considered as a problem,
	// but it still worth to notify about findings.
	SeverityInfo

	// SeverityProblem means a failed test should be considered as
	// a non-blocking problem (which could be solved afterwards).
	SeverityProblem

	// SeverityBlocker means a failed test should be considered as a blocker
	// problem, and the flow should not be continued until the problem is fixed.
	SeverityBlocker
)

func (s Severity) FailureExitCode() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityProblem:
		return 1
	case SeverityBlocker:
		return 2
	}

	return -2 // -1  in our tool is reserved for global unknown error code.
}

// FailureDescription explains how to interpret the Severity.
func (s Severity) FailureDescription() string {
	switch s {
	case SeverityInfo:
		return "nothing important failed, but test results still should be reported"
	case SeverityProblem:
		return "a minor problem was found, but it should not block the flow"
	case SeverityBlocker:
		return "a major problem was found, it is required to fix that, before continuing the flow"
	}

	return "unknown severity"
}

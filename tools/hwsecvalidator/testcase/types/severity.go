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

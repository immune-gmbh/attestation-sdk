package amd

import (
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/hwsecvalidator/testcase/validator"
)

// NewPSPSignatureVerificationFailedSELValidator creates Validator that expects a signature verification failed SEL event
func NewPSPSignatureVerificationFailedSELValidator() validator.Validator {
	return validator.MustExpectSEL(".*PSB_STS.*BIOS RTM Signature verification failed.*", ".*PSB_STS.*PSB Pass Assertion.*")
}

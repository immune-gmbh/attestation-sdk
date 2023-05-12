package identity

import (
	"context"
	"crypto/x509"
)

type Identity interface {
	TLSChain() []x509.Certificate
}

// NewIdentitiesFromContext for some code to extract client identities from a context.
//
// Initially there was a code hardcoded to the infra of a company, and if any other
// company wants to do something with this code, they can replace the function with
// something specific to them.
var NewIdentitiesFromContext = func(ctx context.Context) ([]Identity, error) {
	return nil, nil
}

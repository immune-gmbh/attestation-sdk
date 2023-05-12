package types

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/caching_policy"
)

// CachingPolicy defines if a cache should be used
//
// TODO: move this value into the context
type CachingPolicy int

const (
	// CachingPolicyDefault means that the receiving side may chose the policy.
	CachingPolicyDefault = CachingPolicy(iota)

	// CachingPolicyDisable disables cache.
	CachingPolicyDisable

	// CachingPolicyUse enforces only to re-use existing cache, but to do not update it.
	CachingPolicyUse

	// CachingPolicyStore enforces only to update cache, but do not use it.
	CachingPolicyStore

	// CachingPolicyUseAndStore enables cache.
	CachingPolicyUseAndStore
)

// String implements fmt.Stringer.
func (policy CachingPolicy) String() string {
	switch policy {
	case CachingPolicyDefault:
		return "default"
	case CachingPolicyDisable:
		return "disabled"
	case CachingPolicyUse:
		return "use"
	case CachingPolicyStore:
		return "store"
	case CachingPolicyUseAndStore:
		return "use_and_store"
	}

	return fmt.Sprintf("unknown_caching_policy_%d", policy)
}

// ShouldStore returns if a cache should be updated.
func (policy CachingPolicy) ShouldStore() bool {
	switch policy {
	case CachingPolicyDefault:
		panic("cannot use default caching policy here, required to specify")
	case CachingPolicyDisable:
		return false
	case CachingPolicyUse:
		return false
	case CachingPolicyStore:
		return true
	case CachingPolicyUseAndStore:
		return true
	}

	panic(fmt.Sprintf("invalid caching policy value: %v", policy))
}

// ShouldUse returns if a cache should be used.
func (policy CachingPolicy) ShouldUse() bool {
	switch policy {
	case CachingPolicyDefault:
		panic("cannot use default caching policy here, required to specify")
	case CachingPolicyDisable:
		return false
	case CachingPolicyUse:
		return true
	case CachingPolicyStore:
		return false
	case CachingPolicyUseAndStore:
		return true
	}

	panic(fmt.Sprintf("invalid caching policy value: %v", policy))
}

// CachingPolicyFromThrift convert Thrifty CachingPolicy to the internal one.
func CachingPolicyFromThrift(in caching_policy.CachingPolicy) CachingPolicy {
	switch in {
	case caching_policy.CachingPolicy_Default:
		return CachingPolicyDefault
	case caching_policy.CachingPolicy_NoCache:
		return CachingPolicyDisable
	case caching_policy.CachingPolicy_UseCache:
		return CachingPolicyUse
	case caching_policy.CachingPolicy_StoreAndUseCache:
		return CachingPolicyUseAndStore
	}

	panic(fmt.Sprintf("unknown caching policy: %v", in))
}

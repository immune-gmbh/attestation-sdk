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

import (
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/if/generated/caching_policy"
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

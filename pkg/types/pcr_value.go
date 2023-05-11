package types

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/google/go-tpm/tpm2"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/rtp"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/tpm"
)

// PCRValue represents a single PCR value.
type PCRValue struct {
	Index pcr.ID

	HashAlgo tpm2.Algorithm

	// Value is the PCR value, in terms of EventLog it is called "Digest"
	Value []byte

	Properties Properties `faker:"Properties"`
}

// GoString implements fmt.GoStringer
func (p PCRValue) GoString() string {
	return fmt.Sprintf("%d:%s:%X:%s", p.Index, p.HashAlgo, p.Value, p.Properties.GoString())
}

// Equals returns true if (and only if) PCRValues are equal
func (p PCRValue) Equals(other PCRValue) bool {
	return (p.Index == other.Index &&
		p.HashAlgo == other.HashAlgo &&
		bytes.Equal(p.Value, other.Value) &&
		p.Properties.Equals(other.Properties))
}

// PCRBankTag returns PCR tag for this PCRValue
func (p *PCRValue) PCRBankTag() MeasurementTag {
	determineMeasurementTag := func(idx pcr.ID, hashAlgo tpm2.Algorithm) MeasurementTag {
		switch {
		case idx == 0 && hashAlgo == tpm2.AlgSHA1:
			return PCR0SHA1Tag
		case idx == 0 && hashAlgo == tpm2.AlgSHA256:
			return PCR0SHA256Tag
		case idx == 1 && hashAlgo == tpm2.AlgSHA1:
			return PCR1SHA1Tag
		}
		return 0
	}

	if resultTag := determineMeasurementTag(p.Index, p.HashAlgo); resultTag != 0 {
		return resultTag
	}

	if p.HashAlgo.IsNull() {
		if hashAlgo := DetermineHashAlgorithm(p.Value); !hashAlgo.IsNull() {
			return determineMeasurementTag(p.Index, hashAlgo)
		}
	}
	return 0
}

// NewPCRValue is a simple helper for a PCR value creation
func NewPCRValue(pcrIndex pcr.ID, value []byte, properties ...Property) PCRValue {
	return PCRValue{
		Index:      pcrIndex,
		Value:      value,
		HashAlgo:   DetermineHashAlgorithm(value),
		Properties: properties,
	}
}

// PCRValues is a collection of PCRValue-s
type PCRValues []PCRValue

// GoString implements fmt.GoStringer
func (pcrs PCRValues) GoString() string {
	var r []string
	for _, pcrValue := range pcrs {
		r = append(r, pcrValue.GoString())
	}
	return strings.Join(r, "; ")
}

// Equals returns true if (and only if) PCRValues are equal ignoring the ordering
func (pcrs PCRValues) Equals(other PCRValues) bool {
	if len(pcrs) != len(other) {
		return false
	}

	used := make([]bool, len(other))
	for _, pcr := range pcrs {
		var found bool
		for othIdx, othPCR := range other {
			if used[othIdx] {
				continue
			}
			if pcr.Equals(othPCR) {
				found = true
				used[othIdx] = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// AnyByProperties returns any single PCRValue which has all defined
// properties (returns all pcrs if `props` is empty).
func (pcrs PCRValues) AnyByProperties(props ...Property) *PCRValue {
	for _, pcr := range pcrs {
		if pcr.Properties.ContainsAll(props...) {
			return &pcr
		}
	}
	return nil
}

// ByProperties returns a subset of PCRValue-s which has all defined
// properties (returns all pcrs if `props` is empty).
func (pcrs PCRValues) ByProperties(props ...Property) PCRValues {
	var result PCRValues
	for _, pcr := range pcrs {
		if pcr.Properties.ContainsAll(props...) {
			result = append(result, pcr)
		}
	}
	return result
}

// AnyByValue returns any single PCRValue which has the defined value.
func (pcrs PCRValues) AnyByValue(digest []byte) *PCRValue {
	for _, pcr := range pcrs {
		if bytes.Equal(pcr.Value, digest) {
			return &pcr
		}
	}
	return nil
}

// ByValue returns a subset of PCRValue-s which has the defined value.
func (pcrs PCRValues) ByValue(digest []byte) []PCRValue {
	var result PCRValues
	for _, pcr := range pcrs {
		if bytes.Equal(pcr.Value, digest) {
			result = append(result, pcr)
		}
	}
	return result
}

// ToThrift converts PCRValues to the Thrift format.
func (pcrs PCRValues) ToThrift() []*rtp.PCRValue {
	if len(pcrs) == 0 && pcrs != nil {
		return []*rtp.PCRValue{}
	}
	result := make([]*rtp.PCRValue, 0, len(pcrs))
	for _, pcr := range pcrs {
		result = append(result, &rtp.PCRValue{
			Index: int8(pcr.Index),
			Digest: &tpm.Digest_{
				HashAlgo: tpm.Algo(pcr.HashAlgo),
				Digest:   pcr.Value,
			},
			Properties: &[]rtp.PCRProperties{pcr.Properties.ToThrift()}[0],
		})
	}
	return result
}

// FromThrift converts PCRValues from the Thrift format.
func (pcrs *PCRValues) FromThrift(in []*rtp.PCRValue) {
	*pcrs = (*pcrs)[:0]
	for _, inPCR := range in {
		pcr := PCRValue{
			Index: pcr.ID(inPCR.Index),
		}
		if inPCR.Digest != nil {
			pcr.HashAlgo = tpm2.Algorithm(inPCR.Digest.HashAlgo)
			pcr.Value = inPCR.Digest.Digest
		}
		if inPCR.Properties != nil {
			pcr.Properties.FromThrift(*inPCR.Properties)
		}
		*pcrs = append(*pcrs, pcr)
	}
}

// DetermineHashAlgorithm determines hash algorithm of pcr value
func DetermineHashAlgorithm(pcr []byte) tpm2.Algorithm {
	switch len(pcr) {
	case sha1.Size:
		return tpm2.AlgSHA1
	case sha256.Size:
		return tpm2.AlgSHA256
	}
	return tpm2.AlgUnknown
}

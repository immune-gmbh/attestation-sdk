package models

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/immune-gmbh/attestation-sdk/pkg/types"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
)

// ReproducedPCRs represents a single row `reproduced_pcrs` table
type ReproducedPCRs struct {
	ID              uint64          `db:"id,pk"`
	HashStable      types.HashValue `db:"hash_stable"`
	Registers       string          `db:"registers"`
	RegistersSHA512 types.HashValue `db:"registers_sha512"`
	TPMDevice       string          `db:"tpm_device"`
	PCR0SHA1        []byte          `db:"pcr0_sha1"`
	PCR0SHA256      []byte          `db:"pcr0_sha256"`
	Timestamp       time.Time       `db:"timestamp"`
}

// ParseResgisters returns unmarshalled registers
func (r ReproducedPCRs) ParseResgisters() (registers.Registers, error) {
	if len(r.Registers) == 0 {
		return nil, nil
	}

	var regs registers.Registers
	if err := json.Unmarshal([]byte(r.Registers), &regs); err != nil {
		return nil, err
	}
	return regs, nil
}

// ParseTPMDevice returns detected TPM device
func (r ReproducedPCRs) ParseTPMDevice() (tpmdetection.Type, error) {
	return fromTPMType(tpmType(r.TPMDevice))
}

// NewReproducedPCRs creates a new ReproducedPCRs object
func NewReproducedPCRs(
	hashStable types.HashValue,
	regs registers.Registers,
	tpmDevice tpmdetection.Type,
	pcr0SHA1 []byte,
	pcr0SHA256 []byte,
) (ReproducedPCRs, error) {
	tpm, err := toTPMType(tpmDevice)
	if err != nil {
		return ReproducedPCRs{}, err
	}

	sort.Slice(regs, func(i, j int) bool {
		return regs[i].ID() < regs[j].ID()
	})
	regsMarshalled, err := json.Marshal(regs)
	if err != nil {
		return ReproducedPCRs{}, fmt.Errorf("failed to marshal registers to json: '%w'", err)
	}
	registersSHA512, err := getRegistersKey(regs)
	if err != nil {
		return ReproducedPCRs{}, err
	}

	return ReproducedPCRs{
		HashStable:      hashStable,
		Registers:       string(regsMarshalled),
		RegistersSHA512: registersSHA512,
		TPMDevice:       string(tpm),
		PCR0SHA1:        pcr0SHA1,
		PCR0SHA256:      pcr0SHA256,
	}, nil
}

// UniqueKey represents a unique search index for reproduced_pcrs table
type UniqueKey struct {
	HashStable      types.HashValue
	RegistersSHA512 types.HashValue
	TPMDevice       string
}

// NewUniqueKey create a new UniqueKey object
func NewUniqueKey(
	hashStable types.HashValue,
	regs registers.Registers,
	tpmDevice tpmdetection.Type,
) (UniqueKey, error) {
	tpm, err := toTPMType(tpmDevice)
	if err != nil {
		return UniqueKey{}, err
	}

	sort.Slice(regs, func(i, j int) bool {
		return regs[i].ID() < regs[j].ID()
	})
	registersSHA512, err := getRegistersKey(regs)
	if err != nil {
		return UniqueKey{}, err
	}

	return UniqueKey{
		HashStable:      hashStable,
		RegistersSHA512: registersSHA512,
		TPMDevice:       string(tpm),
	}, nil
}

func getRegistersKey(regs registers.Registers) (types.HashValue, error) {
	if !sort.SliceIsSorted(regs, func(i, j int) bool {
		return regs[i].ID() < regs[j].ID()
	}) {
		panic("registers are not sorted")
	}

	h := sha512.New()
	for _, reg := range regs {
		h.Write([]byte(reg.ID()))
		b, err := registers.ValueBytes(reg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal register: '%s', err: '%w'", reg.ID(), err)
		}
		h.Write(b)
	}
	return types.HashValue(h.Sum(nil)), nil
}

type tpmType string

const (
	unknownTPMType tpmType = "unknown"
	tpm12Type      tpmType = "1.2"
	tpm20Type      tpmType = "2.0"
)

func toTPMType(in tpmdetection.Type) (tpmType, error) {
	switch in {
	case tpmdetection.TypeNoTPM:
		return unknownTPMType, nil
	case tpmdetection.TypeTPM12:
		return tpm12Type, nil
	case tpmdetection.TypeTPM20:
		return tpm20Type, nil
	}
	return unknownTPMType, fmt.Errorf("unknown TPM type: '%v'", in)
}

func fromTPMType(in tpmType) (tpmdetection.Type, error) {
	switch in {
	case unknownTPMType:
		return tpmdetection.TypeNoTPM, nil
	case tpm12Type:
		return tpmdetection.TypeTPM12, nil
	case tpm20Type:
		return tpmdetection.TypeTPM20, nil
	}
	return tpmdetection.TypeNoTPM, fmt.Errorf("unknown TPM type: '%v'", in)
}

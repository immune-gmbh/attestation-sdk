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
package xtpmeventlog

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
)

/*
The initial description of the structure is:

	type EventData struct {
		DescriptionSize   uint16
		DescriptionString [DescriptionSize]uint8
		ACM_POLICY_STATUS uint64
		ACMHeaderSVN      uint16
		ACMSignatureAlgo  TPM_ALG_ID
		ACMSignatureSize  uint16 // to know the size of the signature, to know where it ends
		ACMSignature      [ACMSignatureSize]uint8
		KMSignatureAlgo   TPM_ALG_ID
		KMSignatureSize   uint16 // to know the size of the signature, to know where it ends
		KMSignature       [KMSignatureSize ]uint8
		BPMSignatureAlgo  TPM_ALG_ID
		BPMSignatureSize  uint16 // to know the size of the signature, to know where it ends
		BPMSignature      [BPMSignatureSize]uint8
		IBBDigests        TPML_DIGEST_VALUES
		OriginalPCR0      TPML_DIGEST_VALUES
	}
*/
type PCR0DATALog struct {
	Description       string
	ACM_POLICY_STATUS uint64
	ACMHeaderSVN      uint16
	ACMSignatureAlgo  TPM_ALG_ID
	ACMSignature      []byte `count_type:"uint16_le"`
	KMSignatureAlgo   TPM_ALG_ID
	KMSignature       []byte `count_type:"uint16_le"`
	BPMSignatureAlgo  TPM_ALG_ID
	BPMSignature      []byte `count_type:"uint16_le"`
	IBBDigests        TPML_DIGEST_VALUES
	OriginalPCR0      TPML_DIGEST_VALUES
}

// re-used from https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
type TPM_ALG_ID = cbnt.Algorithm

// re-used from https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
type TPML_DIGEST_VALUES struct {
	Digests []TPMT_HA `count_type:"uint32_le"`
}

// re-used from https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
type TPMT_HA struct {
	HashAlg TPMI_ALG_HASH
	Digest  TPMU_HA
}

// see https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
type TPMU_HA struct {
	Digest []byte
}

// According to documentation TPMI_ALG_HASH is an enumeration, thus
// we assume it has the same size as TPM_ALG_ID.
type TPMI_ALG_HASH = TPM_ALG_ID

// OriginalPCR0ForHash returns the original PCR0 (right after PCR0_DATA measurement) for
// a specified hashing algorithm PCR0 bank.
//
// This is a value of low importance. It allows to simplify diagnostics if PCR0_DATA
// measurement was wrong (or even missing).
// The idea is that when something is wrong and our bruteforcers do no help, we at least
// may see if the problem with measurements is in PCR0_DATA or after it
// (which should help with diagnostics and reduce time-to-understand an issue).
func (s *PCR0DATALog) OriginalPCR0ForHash(hashAlgo cbnt.Algorithm) []byte {
	for _, origPCR0 := range s.OriginalPCR0.Digests {
		if origPCR0.HashAlg == hashAlgo {
			return origPCR0.Digest.Digest
		}
	}
	return nil
}

// Measurement returns the PCR0_DATA pcr.Measurement expected according to the EventLog entry.
func (s *PCR0DATALog) Measurement(hashAlgo cbnt.Algorithm) (*pcr.Measurement, error) {
	var acmPolicyStatus, acmHeaderSVN bytes.Buffer
	err := binary.Write(&acmPolicyStatus, binary.LittleEndian, s.ACM_POLICY_STATUS)
	if err != nil {
		return nil, fmt.Errorf("unable to write ACM_POLICY_STATUS to a temporary buffer: %w", err)
	}

	err = binary.Write(&acmHeaderSVN, binary.LittleEndian, s.ACMHeaderSVN)
	if err != nil {
		return nil, fmt.Errorf("unable to write ACM header SVN to a temporary buffer: %w", err)
	}

	var ibbDigest []byte
	for _, _ibbDigest := range s.IBBDigests.Digests {
		if _ibbDigest.HashAlg == hashAlgo {
			ibbDigest = _ibbDigest.Digest.Digest
			break
		}
	}

	if ibbDigest == nil {
		return nil, fmt.Errorf("unable to find IBB digest of hash algo %v", hashAlgo)
	}

	return &pcr.Measurement{
		ID: pcr.MeasurementIDPCR0DATA,
		Data: pcr.DataChunks{
			{
				ID:        pcr.DataChunkIDACMPolicyStatus,
				ForceData: acmPolicyStatus.Bytes(),
			},
			{
				ID:        pcr.DataChunkIDACMHeaderSVN,
				ForceData: acmHeaderSVN.Bytes(),
			},
			{
				ID:        pcr.DataChunkIDACMSignature,
				ForceData: s.ACMSignature,
			},
			{
				ID:        pcr.DataChunkIDKeyManifestSignature,
				ForceData: s.KMSignature,
			},
			{
				ID:        pcr.DataChunkIDBootPolicyManifestSignature,
				ForceData: s.BPMSignature,
			},
			{
				ID:        pcr.DataChunkIDIBBDigest,
				ForceData: ibbDigest,
			},
		},
	}, nil
}

// ParsePCR0DATALog parses PCR0_DATA log entry data to pcr.Measurement.
func ParsePCR0DATALog(logEntry []byte) (*PCR0DATALog, error) {
	r := bytes.NewReader(logEntry)
	s := PCR0DATALog{}

	var u16 uint16
	if err := binary.Read(r, binary.LittleEndian, &u16); err != nil {
		return nil, fmt.Errorf("unable to read description string length: %w", err)
	}

	description := make([]byte, u16)
	if err := binary.Read(r, binary.LittleEndian, &description); err != nil {
		return nil, fmt.Errorf("unable to read description string (length: %d): %w", len(description), err)
	}
	s.Description = string(description)

	if err := binary.Read(r, binary.LittleEndian, &s.ACM_POLICY_STATUS); err != nil {
		return nil, fmt.Errorf("unable to read ACM_POLICY_STATUS: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &s.ACMHeaderSVN); err != nil {
		return nil, fmt.Errorf("unable to read ACMHeaderSVN: %w", err)
	}

	if err := parseSignature(r, &s.ACMSignatureAlgo, &s.ACMSignature); err != nil {
		return nil, fmt.Errorf("uanble to read BPM data: %w", err)
	}

	if err := parseSignature(r, &s.KMSignatureAlgo, &s.KMSignature); err != nil {
		return nil, fmt.Errorf("uanble to read BPM data: %w", err)
	}

	if err := parseSignature(r, &s.BPMSignatureAlgo, &s.BPMSignature); err != nil {
		return nil, fmt.Errorf("uanble to read BPM data: %w", err)
	}

	if err := parseDigests(r, &s.IBBDigests); err != nil {
		return nil, fmt.Errorf("unable to read IBBDigests: %w", err)
	}

	if err := parseDigests(r, &s.OriginalPCR0); err != nil {
		return nil, fmt.Errorf("unable to read OriginalPCR0: %w", err)
	}

	return &s, nil
}

func hashSize(algo cbnt.Algorithm) (uint, error) {
	h, err := algo.Hash()
	if err != nil {
		return 0, fmt.Errorf("unable to get the hash info: %w", err)
	}
	return uint(h.Size()), nil
}

func parseSignature(r io.Reader, algo *TPM_ALG_ID, signature *[]byte) error {
	if err := binary.Read(r, binary.LittleEndian, algo); err != nil {
		return fmt.Errorf("unable to read the algorithm ID: %w", err)
	}

	var count uint16
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return fmt.Errorf("unable to read the count value: %w", err)
	}
	*signature = make([]byte, count)

	if err := binary.Read(r, binary.LittleEndian, *signature); err != nil {
		return fmt.Errorf("unable to read the signature (length: %d): %w", len(*signature), err)
	}

	return nil
}

func parseDigests(r io.Reader, digests *TPML_DIGEST_VALUES) error {
	var u32 uint32

	if err := binary.Read(r, binary.LittleEndian, &u32); err != nil {
		return fmt.Errorf("unable to read amount of digests: %w", err)
	}
	digests.Digests = make([]TPMT_HA, u32)

	for idx := range digests.Digests {
		digest := &digests.Digests[idx]
		if err := binary.Read(r, binary.LittleEndian, &digest.HashAlg); err != nil {
			return fmt.Errorf("unable to read [%d].HashAlg: %w", idx, err)
		}

		digest.Digest.Digest = make([]byte, sha512.Size)

		if err := binary.Read(r, binary.LittleEndian, &digest.Digest.Digest); err != nil {
			return fmt.Errorf("unable to read [%d].Digest (length: %d)", len(digest.Digest.Digest), err)
		}

		if digest.HashAlg != cbnt.AlgUnknown {
			size, err := hashSize(digest.HashAlg)
			if err != nil {
				return fmt.Errorf("do not know size of [%d].Digest: %w", idx, err)
			}
			digest.Digest.Digest = digest.Digest.Digest[:size]
		}
	}

	return nil
}

// ExtractPCR0DATALog extracts raw PCR0_DATA measurements from EventLog (if it is there).
func ExtractPCR0DATALog(
	eventLog *tpmeventlog.TPMEventLog,
	hashAlgo tpmeventlog.TPMAlgorithm,
) (*PCR0DATALog, []byte, error) {
	events, err := eventLog.FilterEvents(0, hashAlgo)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to filter events: %w", err)
	}

	for _, event := range events {
		if !pcr.TPMEventTypeToMeasurementIDs(0, event.Type).Contains(pcr.MeasurementIDPCR0DATA) {
			continue
		}

		var digest []byte
		if event.Digest != nil {
			digest = event.Digest.Digest
		}

		if len(event.Data) < int(unsafe.Sizeof(PCR0DATALog{})) {
			// unsafe.Sizeof seems to be good enough for rough estimation.
			return nil, digest, ErrPCR0DataLogTooSmall{Data: event.Data}
		}

		pcr0DataLog, err := ParsePCR0DATALog(event.Data)
		return pcr0DataLog, digest, err
	}

	return nil, nil, ErrNoPCR0DATALog{}
}

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
package typeconv

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/flows"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/measurements"
	thrift_tpm "github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/tpm"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	pcr_types "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// FromThriftFlow converts firmware analysis service Flow to pcr0tool Flow
func FromThriftFlow(flow measurements.Flow) (types.Flow, error) {
	switch flow {
	case measurements.Flow_AUTO:
		return flows.Root, nil
	case measurements.Flow_INTEL_LEGACY_TXT_DISABLED:
		return flows.IntelLegacyTXTDisabled, nil
	case measurements.Flow_INTEL_LEGACY_TXT_ENABLED:
		return flows.IntelLegacyTXTEnabled, nil
	case measurements.Flow_INTEL_LEGACY_TPM12_TXT_ENABLED:
		return flows.IntelLegacyTXTEnabledTPM12, nil
	case measurements.Flow_INTEL_CBNT0T:
		return flows.IntelCBnT, nil
	case measurements.Flow_AMD_MILAN_LEGACY_LOCALITY_0:
		return flows.AMDMilanLegacyLocality0, nil
	case measurements.Flow_AMD_MILAN_LEGACY_LOCALITY_3:
		return flows.AMDMilanLegacyLocality3, nil
	case measurements.Flow_AMD_MILAN_LOCALITY_0:
		return flows.AMDMilanLocality0, nil
	case measurements.Flow_AMD_MILAN_LOCALITY_3:
		return flows.AMDMilanLocality3, nil
	case measurements.Flow_AMD_GENOA_LOCALITY_0:
		return flows.AMDGenoaLocality0, nil
	case measurements.Flow_AMD_GENOA_LOCALITY_3:
		return flows.AMDGenoaLocality3, nil
	}
	return flows.Root, fmt.Errorf("unknown flow: %d", flow)
}

// ToThriftFlow converts pcr0tool Flow to firmware analysis service Flow
func ToThriftFlow(flow types.Flow) (measurements.Flow, error) {
	switch flow.Name {
	case flows.Root.Name:
		return measurements.Flow_AUTO, nil
	case flows.IntelLegacyTXTDisabled.Name:
		return measurements.Flow_INTEL_LEGACY_TXT_DISABLED, nil
	case flows.IntelLegacyTXTEnabled.Name:
		return measurements.Flow_INTEL_LEGACY_TXT_ENABLED, nil
	case flows.IntelLegacyTXTEnabledTPM12.Name:
		return measurements.Flow_INTEL_LEGACY_TPM12_TXT_ENABLED, nil
	case flows.IntelCBnT.Name:
		return measurements.Flow_INTEL_CBNT0T, nil
	case flows.AMDMilanLegacyLocality0.Name:
		return measurements.Flow_AMD_MILAN_LEGACY_LOCALITY_0, nil
	case flows.AMDMilanLegacyLocality3.Name:
		return measurements.Flow_AMD_MILAN_LEGACY_LOCALITY_3, nil
	case flows.AMDMilanLocality0.Name:
		return measurements.Flow_AMD_MILAN_LOCALITY_0, nil
	case flows.AMDMilanLocality3.Name:
		return measurements.Flow_AMD_MILAN_LOCALITY_3, nil
	case flows.AMDGenoaLocality0.Name:
		return measurements.Flow_AMD_GENOA_LOCALITY_0, nil
	case flows.AMDGenoaLocality3.Name:
		return measurements.Flow_AMD_GENOA_LOCALITY_3, nil
	}
	return measurements.Flow_AUTO, fmt.Errorf("unknown flow: '%s'", flow.Name)
}

// ToThriftTPMType converts pcr0tool TPMType to firmware analysis service TPMType
func ToThriftTPMType(tpmType tpmdetection.Type) (afas.TPMType, error) {
	switch tpmType {
	case tpmdetection.TypeNoTPM:
		return afas.TPMType_UNKNOWN, nil
	case tpmdetection.TypeTPM12:
		return afas.TPMType_TPM12, nil
	case tpmdetection.TypeTPM20:
		return afas.TPMType_TPM20, nil
	}
	return afas.TPMType_UNKNOWN, fmt.Errorf("unknown tpm type: %d", tpmType)
}

// FromThriftTPMType converts firmware analysis service TPMType to pcr0tool TPMType
func FromThriftTPMType(tpmType afas.TPMType) (tpmdetection.Type, error) {
	switch tpmType {
	case afas.TPMType_UNKNOWN:
		return tpmdetection.TypeNoTPM, nil
	case afas.TPMType_TPM12:
		return tpmdetection.TypeTPM12, nil
	case afas.TPMType_TPM20:
		return tpmdetection.TypeTPM20, nil
	}
	return tpmdetection.TypeNoTPM, fmt.Errorf("unknown tpm type: %d", tpmType)
}

// FromThriftRegisters converts firmware analysis status registers to pcr0tool registers
func FromThriftRegisters(statusRegisters []*afas.StatusRegister) (registers.Registers, error) {
	if statusRegisters == nil {
		return nil, nil
	}

	var resultErr errors.MultiError
	result := make(registers.Registers, 0, len(statusRegisters))
	for _, statusRegister := range statusRegisters {
		reg, err := registers.ValueFromBytes(registers.RegisterID(statusRegister.ID), statusRegister.Value)
		if err != nil {
			resultErr.Add(fmt.Errorf("unable to decode register <%v:%v>: %w", statusRegister.ID, statusRegister.Value, err))
			continue
		}
		result = append(result, reg)
	}
	return result, resultErr.ReturnValue()
}

// ToThriftRegisters converts pcr0tool registers to firmware analysis status registers
func ToThriftRegisters(statusRegisters registers.Registers) ([]*afas.StatusRegister, error) {
	if statusRegisters == nil {
		return nil, nil
	}

	var resultErr errors.MultiError
	result := make([]*afas.StatusRegister, 0, len(statusRegisters))
	for _, statusRegister := range statusRegisters {
		b, err := registers.ValueBytes(statusRegister)
		if err != nil {
			resultErr.Add(fmt.Errorf("unable to encode register %v", statusRegister.ID()))
			continue
		}
		result = append(result, &afas.StatusRegister{
			ID:    string(statusRegister.ID()),
			Value: b,
		})
	}
	return result, resultErr.ReturnValue()
}

// ToThriftTPMEventLog converts pcr0tool TPMEventLog to the firmware analysis service format.
func ToThriftTPMEventLog(in *tpmeventlog.TPMEventLog) *thrift_tpm.EventLog {
	if in == nil {
		return nil
	}

	out := &thrift_tpm.EventLog{
		Events: make([]*thrift_tpm.Event, 0, len(in.Events)),
	}
	for _, event := range in.Events {
		var digest *thrift_tpm.Digest_
		if event.Digest != nil {
			digest = &thrift_tpm.Digest_{
				HashAlgo: thrift_tpm.Algo(event.Digest.HashAlgo),
				Digest:   event.Digest.Digest,
			}
		}

		out.Events = append(out.Events, &thrift_tpm.Event{
			PCRIndex: int8(event.PCRIndex),
			Type:     int32(event.Type),
			Data:     event.Data,
			Digest:   digest,
		})
	}

	return out
}

// FromThriftTPMEventLog converts firmware analysis service TPMEventLog to the converged security suite format.
func FromThriftTPMEventLog(in *thrift_tpm.EventLog) *tpmeventlog.TPMEventLog {
	if in == nil {
		return nil
	}

	out := &tpmeventlog.TPMEventLog{
		Events: make([]*tpmeventlog.Event, 0, len(in.Events)),
	}
	for _, event := range in.Events {
		var digest *tpmeventlog.Digest
		if event.Digest != nil {
			digest = &tpmeventlog.Digest{
				HashAlgo: tpmeventlog.TPMAlgorithm(event.Digest.HashAlgo),
				Digest:   event.Digest.Digest,
			}
		}

		out.Events = append(out.Events, &tpmeventlog.Event{
			PCRIndex: pcr_types.ID(event.PCRIndex),
			Type:     tpmeventlog.EventType(event.Type),
			Data:     event.Data,
			Digest:   digest,
		})
	}

	return out
}

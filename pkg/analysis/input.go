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

package analysis

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"reflect"

	bootflowtypes "github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmdetection"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/hashicorp/go-multierror"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/xjson"
)

// Input specifies input data for analysis
type Input map[TypeID]any

// GoString implements fmt.GoStringer
func (in Input) GoString() string {
	b, err := in.MarshalJSON()
	if err != nil {
		return "<unable to serialize>"
	}
	return string(b)
}

// MarshalJSON implements json.Marshaler
func (in Input) MarshalJSON() ([]byte, error) {
	m := make(map[TypeID]json.RawMessage, len(in))
	for typeID, value := range in {
		if old, alreadySet := m[typeID]; alreadySet {
			// Assumebly this should never happen, because ID consists of pkgpath + name,
			// which should be guaranteed to be unique.
			panic(fmt.Errorf("internal error: types %T and %T has the same ID: '%s'", old, value, typeID))
		}

		b, err := xjson.MarshalWithTypeIDs(value, TypeRegistry())
		if err != nil {
			return nil, fmt.Errorf("unable to serialize %#+v: %w", value, err)
		}
		m[typeID] = b
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements json.Unmarshaler
func (in *Input) UnmarshalJSON(b []byte) error {
	var retErr error

	var m map[TypeID]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("unable to deserialize JSON '%s': %w", b, err)
	}

	typeRegistry := TypeRegistry()
	for id, unparsedValue := range m {
		value, err := typeRegistry.NewByTypeID(id)
		if err != nil {
			retErr = multierror.Append(retErr, fmt.Errorf("unable to create a new instance given type ID '%s': %w", id, err))
			continue
		}
		err = xjson.UnmarshalWithTypeIDs(unparsedValue, value, typeRegistry)
		if err != nil {
			retErr = multierror.Append(retErr, fmt.Errorf("unable to un-JSON-ize value '%s' of field '%s': %w", unparsedValue, id, err))
			continue
		}
		(*in)[id] = value
	}

	return retErr
}

// Scan implements database/sql.Scanner
// TODO: remove this from this package. Package `analysis` should be agnostic of this stuff.
func (in *Input) Scan(src any) error {
	if src == nil {
		*in = (Input)(nil)
		return nil
	}

	var b []byte
	switch src := src.(type) {
	case string:
		b = []byte(src)
	case []byte:
		b = src
	default:
		return fmt.Errorf("expected string or []byte, but received %T", src)
	}

	return in.UnmarshalJSON([]byte(b))
}

// Value implements database/sql/driver.Valuer
// TODO: remove this from this package. Package `analysis` should be agnostic of this stuff.
func (in Input) Value() (driver.Value, error) {
	if in == nil {
		return nil, nil
	}

	b, err := in.MarshalJSON()
	return string(b), err
}

// AddOriginalFirmware adds the original firmware image
func (in Input) AddOriginalFirmware(image Blob) Input {
	return in.AddCustomValue(NewOriginalFirmwareBlob(image))
}

// AddActualFirmware adds the actual firmware image
func (in Input) AddActualFirmware(image Blob) Input {
	return in.AddCustomValue(NewActualFirmwareBlob(image))
}

// AddActualRegisters adds the actual registers
func (in Input) AddActualRegisters(regs ActualRegisters) Input {
	return in.AddCustomValue(regs)
}

// AddTPMDevice adds inormation about the TPM device
func (in Input) AddTPMDevice(tpm tpmdetection.Type) Input {
	return in.AddCustomValue(tpm)
}

// AddTPMEventLog adds information about the TPM event log
func (in Input) AddTPMEventLog(eventLog *tpmeventlog.TPMEventLog) Input {
	return in.AddCustomValue(eventLog)
}

// AddActualPCR0 adds information about existing PCR0 value on a host
func (in Input) AddActualPCR0(pcr []byte) Input {
	return in.AddCustomValue(ActualPCR0(pcr))
}

// AddAssetID adds information about asset id of a host
func (in Input) AddAssetID(assetID int64) Input {
	return in.AddCustomValue(AssetID(assetID))
}

// AddActualBIOSInfo adds SMBIOS info about the actual BIOS firmware.
func (in Input) AddActualBIOSInfo(biosInfo ActualBIOSInfo) Input {
	return in.AddCustomValue(biosInfo)
}

// AddOriginalBIOSInfo adds SMBIOS info about the original BIOS firmware.
func (in Input) AddOriginalBIOSInfo(biosInfo OriginalBIOSInfo) Input {
	return in.AddCustomValue(biosInfo)
}

// AddCustomValue adds a custom value as some plugins take unique values
//
// Note: register custom values through RegisterInputType, to make them
//
//	deserializable.
func (in Input) AddCustomValue(v any) Input {
	if !IsRegisteredType(v) {
		panic(fmt.Errorf("internal error: input value of type %T is not registered", v))
	}
	typID := typeIDOf(v)
	if oldValue, ok := in[typID]; ok {
		if reflect.TypeOf(oldValue) != reflect.TypeOf(v) {
			// typeIDOf guarantees to provide different typeID for different types, this should never happen
			panic(fmt.Errorf("internal error: TypeID collision between %T and %T: TypeID is '%s'", oldValue, v, typID))
		}
	}
	in[typID] = v
	return in
}

// ForceBootFlow adds information about the bootflow
func (in Input) ForceBootFlow(_flow bootflowtypes.Flow) Input {
	flow := types.BootFlow(_flow)
	in[typeIDOf(flow)] = flow
	return in
}

// NewInput creates a new Inout object
func NewInput() Input {
	return make(map[TypeID]any)
}

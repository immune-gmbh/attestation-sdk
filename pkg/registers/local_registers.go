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
package registers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/dmidecode"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/go-linux-lowlevel-hw/pkg/hwapi"
	"github.com/digitalocean/go-smbios/smbios"
	"github.com/klauspost/cpuid"
)

const (
	odmSMBIOSType    = 11
	mpoC2PMSG37Index = 13
	mpoC2PMSG38Index = 14
)

func amdLocalRegisters() (registers.Registers, error) {
	// The registers are stored in SMBIOS table with type 11, here is the example:
	// Handle 0x003B, DMI type 11, 5 bytes
	// OEM Strings
	// String 1: 02-000423
	// String 2: 01-005624
	// String 3: North Dome EVT2
	// String 4: To be filled by O.E.M.
	// String 5: 0x02B5E777-F1B90015
	// String 6: 0xFFFFFFFF-FFFFFFFF
	// String 7: 02-000424
	// String 8: To be filled by O.E.M.
	// String 9: To be filled by O.E.M.
	// String 10: To be filled by O.E.M.
	// String 11: To be filled by O.E.M.
	// String 12: To be filled by O.E.M.
	// String 13: 0.13.0.5b
	// String 14: 0x1100008D # MP0_C2P_MSG_37
	// String 15: 0x50000000 # MP0_C2P_MSG_38

	localDMI, err := dmidecode.LocalDMITable()
	if err != nil {
		return nil, err
	}

	var odmSMBIOS *smbios.Structure
	for _, smbios := range localDMI.SMBIOSStructs {
		if smbios.Header.Type == odmSMBIOSType {
			odmSMBIOS = smbios
		}
	}
	if odmSMBIOS == nil {
		return nil, nil
	}

	var result registers.Registers
	if len(odmSMBIOS.Strings) > mpoC2PMSG37Index {
		v, err := parseDMIDecodeRegisterValue(odmSMBIOS.Strings[mpoC2PMSG37Index])
		if err != nil {
			return nil, err
		}
		result = append(result, registers.ParseMP0C2PMsg37Register(uint32(v)))
	}
	if len(odmSMBIOS.Strings) > mpoC2PMSG38Index {
		v, err := parseDMIDecodeRegisterValue(odmSMBIOS.Strings[mpoC2PMSG38Index])
		if err != nil {
			return nil, err
		}
		result = append(result, registers.ParseMP0C2PMsg38Register(uint32(v)))
	}

	return result, nil
}

func intelLocalRegisters() (registers.Registers, error) {
	txtAPI := hwapi.GetAPI()

	txtConfig, err := registers.FetchTXTConfigSpaceSafe(txtAPI)
	if err != nil {
		return nil, fmt.Errorf("unable to get TXT config space: %w", err)
	}

	var mErr errors.MultiError
	txtRegisters, err := registers.ReadTXTRegisters(txtConfig)
	if err != nil {
		_ = mErr.Add(fmt.Errorf("unable to read TXT registers: %w", err))
	}

	msrRegisters, err := registers.ReadMSRRegisters(&registers.DefaultMSRReader{})
	if err != nil {
		_ = mErr.Add(fmt.Errorf("unable to read MSR registers: %w", err))
	}

	result := append(txtRegisters, msrRegisters...)
	return result, mErr.ReturnValue()
}

func parseDMIDecodeRegisterValue(value string) (uint32, error) {
	regStr := value
	base := 10
	if strings.HasPrefix(regStr, "0x") {
		regStr = regStr[2:]
		base = 16
	}
	var v uint64
	var err error
	if v, err = strconv.ParseUint(regStr, base, 32); err != nil {
		return 0, fmt.Errorf("failed to parse MP0_C2P_MSG_37 '%s' from SMBIOS: %w", value, err)
	}
	return uint32(v), nil
}

// LocalRegisters dumps status registers of the local machine.
func LocalRegisters() (registers.Registers, error) {
	if cpuid.CPU.VendorID == cpuid.AMD {
		return amdLocalRegisters()
	}
	return intelLocalRegisters()
}

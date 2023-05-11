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

package dmidecode

import (
	"fmt"
)

type ErrDMITable struct {
	Err error
}

func (err ErrDMITable) Error() string {
	return fmt.Sprintf("unable to get a DMI table: %v", err.Err)
}

func (err ErrDMITable) Unwrap() error {
	return err.Err
}

// ErrParseFirmware means a problem while parsing a firmware image.
type ErrParseFirmware struct {
	Err error
}

func (err ErrParseFirmware) Error() string {
	return fmt.Sprintf("unable to parse firmware: %v", err.Err)
}

func (err ErrParseFirmware) Unwrap() error {
	return err.Err
}

// ErrFindSMBIOSInFirmware means SMBIOS static data section was not found.
type ErrFindSMBIOSInFirmware struct {
	Err error
}

func (err ErrFindSMBIOSInFirmware) Error() string {
	return fmt.Sprintf("unable to find SMBIOS static data in the firmware: %v", err.Err)
}

func (err ErrFindSMBIOSInFirmware) Unwrap() error {
	return err.Err
}

// ErrUnexpectedNodeType means firmware has an unexpected node type.
type ErrUnexpectedNodeType struct {
	Obj any
}

func (err ErrUnexpectedNodeType) Error() string {
	return fmt.Sprintf("unexpected node type: %T", err.Obj)
}

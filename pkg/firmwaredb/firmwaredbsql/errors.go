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

package firmwaredbsql

import (
	"fmt"

	"github.com/immune-gmbh/attestation-sdk/pkg/firmwaredb"
)

type UnableToOpen struct{}

func (UnableToOpen) String() string { return "unable to open connection to SQL" }

type UnableToScan struct{}

func (UnableToScan) String() string { return "unable to scan" }

type UnableToConnect struct{}

func (UnableToConnect) String() string { return "unable to connect" }

type UnableToPing struct{}

func (UnableToPing) String() string { return "unable to ping" }

type Cancelled struct{}

func (Cancelled) String() string { return "cancelled" }

type UnableToQuery struct {
	Query string
	Args  []any
}

func (e UnableToQuery) String() string {
	return fmt.Sprintf("unable to query '%s' (with args:%v)", e.Query, e.Args)
}

type ErrOpen = firmwaredb.Err[UnableToOpen]
type ErrConnect = firmwaredb.Err[UnableToConnect]
type ErrPing = firmwaredb.Err[UnableToPing]
type ErrCancelled = firmwaredb.Err[Cancelled]
type ErrScan = firmwaredb.Err[UnableToScan]
type ErrQuery = firmwaredb.Err[UnableToQuery]

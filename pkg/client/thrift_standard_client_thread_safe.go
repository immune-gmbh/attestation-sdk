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

package client

import (
	"context"
	"sync"

	"github.com/apache/thrift/lib/go/thrift"
)

type thriftStandardClientThreadSafe struct {
	*thrift.TStandardClient
	Locker sync.Mutex
}

var _ thrift.TClient = (*thriftStandardClientThreadSafe)(nil)

func newThriftStandardClientThreadSafe(
	inputProtocol, outputProtocol thrift.TProtocol,
) *thriftStandardClientThreadSafe {
	return &thriftStandardClientThreadSafe{
		TStandardClient: thrift.NewTStandardClient(inputProtocol, outputProtocol),
	}
}

func (p *thriftStandardClientThreadSafe) Call(
	ctx context.Context,
	method string,
	args, result thrift.TStruct,
) (thrift.ResponseMeta, error) {
	p.Locker.Lock()
	defer p.Locker.Unlock()
	return p.TStandardClient.Call(ctx, method, args, result)
}

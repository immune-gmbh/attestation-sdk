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

package firmwaredbsql

import (
	"fmt"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb"
)

type InvalidURL struct{}

func (InvalidURL) String() string { return "invalid URL" }

type UnableToParseURL struct {
	URL string
}

func (e UnableToParseURL) String() string {
	return fmt.Sprintf("unable to parse URL '%s'", e.URL)
}

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
type ErrURL = firmwaredb.Err[InvalidURL]
type ErrParseURL = firmwaredb.Err[UnableToParseURL]
type ErrConnect = firmwaredb.Err[UnableToConnect]
type ErrPing = firmwaredb.Err[UnableToPing]
type ErrCancelled = firmwaredb.Err[Cancelled]
type ErrScan = firmwaredb.Err[UnableToScan]
type ErrQuery = firmwaredb.Err[UnableToQuery]

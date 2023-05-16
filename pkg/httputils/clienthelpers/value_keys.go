package clienthelpers

type valueKey int

const (
	// ValueKeyLogLevelRemote is the key for Value and WithValue to define
	// the log level on the remote side (on a server).
	ValueKeyLogLevelRemote = valueKey(iota + 1)
)

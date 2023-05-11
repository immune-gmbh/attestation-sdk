package objhash

import (
	"crypto/sha512"
)

// ObjHash is a set of byte which is unique and deterministic for a set
// of input values. It is supposed to be used to distinct incoming requests
// in a memoization algorithms.
//
// The order of variables is also important ("1, 2, 3" != "3, 2, 1").
type ObjHash [blake3Size + sha512.Size]byte

// MustBuild is the same as Build, but expects no error (panics if any).
func MustBuild(args ...interface{}) ObjHash {
	result, err := Build(args)
	if err != nil {
		panic(err)
	}
	return result
}

// Build returns a ObjHash for a set of variables
func Build(args ...interface{}) (ObjHash, error) {
	return NewBuilder().Build(args...)
}

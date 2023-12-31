// Code generated by Thrift Compiler (0.14.0). DO NOT EDIT.

package txt_errors

import (
	"bytes"
	"context"
	"fmt"
	"github.com/apache/thrift/lib/go/thrift"
	"time"
)

// (needed to ensure safety because of naive import list construction.)
var _ = thrift.ZERO
var _ = fmt.Printf
var _ = context.Background
var _ = time.Now
var _ = bytes.Equal

var ErrorDescription map[string]string

func init() {
	ErrorDescription = map[string]string{
		"ErrBPM":          "BPM error",
		"ErrBPMRevoked":   "BPM is revoked (firmware was downgraded to an insecure version, BPM SVN is decreased)",
		"ErrBPTIntegrity": "BPT integrity error",
		"ErrUnknown":      "unknown error",
	}

}

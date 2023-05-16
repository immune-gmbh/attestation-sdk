package formatter

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var logLevelSymbol []byte

func init() {
	logLevelSymbol = make([]byte, len(logrus.AllLevels)+1)
	for _, level := range logrus.AllLevels {
		logLevelSymbol[level] = strings.ToUpper(level.String()[:1])[0]
	}
}

// CompactText is a logrus formatter which prints laconic lines, like
// [12:34 W main.go:56] my message
type CompactText struct {
	TimestampFormat string
	FieldAllowList  []string
}

// Format implements logrus.Formatter.
func (f *CompactText) Format(entry *logrus.Entry) ([]byte, error) {
	var str, header strings.Builder
	timestamp := time.RFC3339
	if f.TimestampFormat != "" {
		timestamp = f.TimestampFormat
	}
	header.WriteString(fmt.Sprintf("%s %c",
		entry.Time.Format(timestamp),
		logLevelSymbol[entry.Level],
	))
	if entry.Caller != nil {
		header.WriteString(fmt.Sprintf(" %s:%d", filepath.Base(entry.Caller.File), entry.Caller.Line))
	}
	str.WriteString(fmt.Sprintf("[%s] %s",
		header.String(),
		entry.Message,
	))

	keys := make([]string, 0, len(entry.Data))
	for key := range entry.Data {
		if f.FieldAllowList != nil {
			found := false
			for _, allowed := range f.FieldAllowList {
				if key == allowed {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		str.WriteString(fmt.Sprintf("\t%s=%v", key, entry.Data[key]))
	}

	str.WriteByte('\n')
	return []byte(str.String()), nil
}

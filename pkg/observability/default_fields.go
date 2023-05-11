package observability

import (
	"os"
	"os/user"
	"strings"

	"github.com/facebookincubator/go-belt/pkg/field"
)

// DefaultFields returns default structured data for observability tooling (logging, tracing, etc)
func DefaultFields() field.Fields {
	var result field.Fields

	result = append(result, field.Field{
		Key:   "pid",
		Value: FieldPID(os.Getpid()),
	})
	result = append(result, field.Field{
		Key:   "uid",
		Value: FieldUID(os.Getuid()),
	})
	if curUser, _ := user.Current(); curUser != nil {
		result = append(result, field.Field{
			Key:   "username",
			Value: FieldUsername(curUser.Name),
		})
	}
	if hostname, err := os.Hostname(); err == nil {
		result = append(result, field.Field{
			Key:   "hostname",
			Value: FieldHostname(hostname),
		})
	}
	if s := os.Getenv("SMC_TIERS"); s != "" {
		result = append(result, field.Field{
			Key:   "smcTiers",
			Value: FieldSMCTiers(strings.Split(s, ",")),
		})
	}
	for keySrc, keyDst := range map[string]string{
		"TW_JOB_CLUSTER": "twJobCluster",
		"TW_JOB_USER":    "twJobUser",
		"TW_JOB_NAME":    "twJobName",
		"TW_TASK_ID":     "twTaskID",
	} {
		if s := os.Getenv(keySrc); s != "" {
			result = append(result, field.Field{
				Key:   keyDst,
				Value: s,
			})
		}
	}

	return result
}

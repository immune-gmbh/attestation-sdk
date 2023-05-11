package main

import (
	"github.com/facebookincubator/go-belt/tool/logger"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

type fianoHook struct{}

func (h fianoHook) ProcessLogEntry(entry *logger.Entry) bool {

	prefix := ""
	switch entry.Level {
	case logger.LevelWarning:
		prefix = "[warn] "
	case logger.LevelError:
		prefix = "[error] "
	default:
		// FianoLogger implements only Warn and Error
		// So, adding default only to be safe
		prefix = "[unknown level] "
	}

	entry.Message = prefix + entry.Message

	return true
}

func (h fianoHook) Flush() {}

func newFianoLogger(l logger.Logger) fianoLog.Logger {
	return l.WithLevel(logger.LevelDebug).WithHooks(fianoHook{})
}

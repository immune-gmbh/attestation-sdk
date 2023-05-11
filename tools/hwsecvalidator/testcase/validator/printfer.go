package validator

type printfer struct {
	printf func(format string, args ...interface{})
}

func (p printfer) Printf(format string, args ...interface{}) {
	p.printf(format, args...)
}

func asPrintfer(fn func(format string, args ...interface{})) printfer {
	return printfer{printf: fn}
}

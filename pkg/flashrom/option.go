//go:build linux
// +build linux

package flashrom

const (
	// DefaultDevMemPath is the default path where to look for the device
	// to access memory by physical addresses.
	DefaultDevMemPath = `/dev/mem`

	// DefaultIOMemPath is the default path to look for the lists ranges
	// of physical memory addresses.
	DefaultIOMemPath = `/proc/iomem`

	// DefaultFlashromPath is the default command for os.Exec to execute
	// "flashrom".
	DefaultFlashromPath = `flashrom`

	// DefaultDevPath is the default path where to look for various
	// devices.
	DefaultDevPath = `/dev`

	// DefaultSysFSMTDPath is the default path to look for sysfs exports
	// of MTD devices.
	DefaultSysFSMTDPath = `/sys/class/mtd`
)

// DumpMethod defines which way to use to dump a firmware image
type DumpMethod int

const (
	// DumpMethodAuto means to pick the method automatically
	DumpMethodAuto = DumpMethod(iota)

	// DumpMethodFlashrom means to use an external tool "flashrom" to dump
	// a firmware image.
	DumpMethodFlashrom

	// DumpMethodFlashrom means to use an external tool "AFULNX64" to dump
	// a firmware image.
	DumpMethodAfulnx64

	// DumpMethodDevMem means to dump a firmware image directly from
	// physical memory ("/dev/mem", see also DefaultDevMemPath and
	// DefaultIOMemPath).
	DumpMethodDevMem

	// DumpMethodMTD means to dump a firmware image using MTD
	// ("/dev/mtd*" and "/sysfs/class/mtd", see also DefaultDevPath and
	// DefaultSysFSMTDPath).
	DumpMethodMTD
)

type config struct {
	DumpMethod                 DumpMethod
	IOMemPath                  string
	DevMemPath                 string
	FlashromPath               string
	Afulnx64Path               string
	FirmwareFallbackLayoutPath string
	DevPath                    string
	SysFSMTDPath               string
}

// Option is an abstract option for flashrom commands.
type Option interface {
	apply(*config)
}

// OptionIOMemPath is an Option which  defines the path to look for the
// lists ranges of physical memory addresses.
type OptionIOMemPath string

func (opt OptionIOMemPath) apply(cfg *config) {
	cfg.IOMemPath = string(opt)
}

// OptionDevMemPath is an Option which defines the path where to look for
// the device to access memory by physical addresses.
type OptionDevMemPath string

func (opt OptionDevMemPath) apply(cfg *config) {
	cfg.DevMemPath = string(opt)
}

// OptionDumpMethod is an Option which defines
// which way to use to dump a firmware image
type OptionDumpMethod DumpMethod

func (opt OptionDumpMethod) apply(cfg *config) {
	cfg.DumpMethod = DumpMethod(opt)
}

// OptionFlashromPath is an Option which defines the command
// for os.Exec to execute tool "flashrom".
type OptionFlashromPath string

func (opt OptionFlashromPath) apply(cfg *config) {
	cfg.FlashromPath = string(opt)
}

// OptionFirmwareFallbackLayoutPath is an Option which defines a path
// to a firmware layout text file.
//
// In case if "flashrom" wasn't able to read the firmware layout table,
// it is possible to use a predefined layout. Such layout could be
// read by tool "ifdtool" using the original image of the firmware.
type OptionFirmwareFallbackLayoutPath string

func (opt OptionFirmwareFallbackLayoutPath) apply(cfg *config) {
	cfg.FirmwareFallbackLayoutPath = string(opt)
}

// OptionAfulnx64Path is an Option which defines the command
// for os.Exec to execute tool "AFULNX64"
type OptionAfulnx64Path string

func (opt OptionAfulnx64Path) apply(cfg *config) {
	cfg.Afulnx64Path = string(opt)
}

// OptionDevPath is an Option which defines where to look for various
// devices.
type OptionDevPath string

func (opt OptionDevPath) apply(cfg *config) {
	cfg.DevPath = string(opt)
}

// OptionSysFSMTDPath is an Option which defines where to look for sysfs exports
// of MTD devices.
type OptionSysFSMTDPath string

func (opt OptionSysFSMTDPath) apply(cfg *config) {
	cfg.SysFSMTDPath = string(opt)
}

func getConfig(opts ...Option) config {
	cfg := config{
		IOMemPath:    DefaultIOMemPath,
		DevMemPath:   DefaultDevMemPath,
		FlashromPath: DefaultFlashromPath,
		DevPath:      DefaultDevPath,
		SysFSMTDPath: DefaultSysFSMTDPath,
	}
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	return cfg
}

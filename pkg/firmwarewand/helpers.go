package firmwarewand

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/generated/afas"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/dmidecode"

	"github.com/facebookincubator/go-belt/pkg/field"
	"github.com/facebookincubator/go-belt/tool/logger"
)

type firmwareVariant struct {
	Version     string
	ReleaseDate string
}

type fwVariantSource int

const (
	fwVariantSourceUndefined = fwVariantSource(iota)
	fwVariantSourceUser
	fwVariantSourceDB
	fwVariantSourceSysfs
	fwVariantSourceImage
)

func (src fwVariantSource) String() string {
	switch src {
	case fwVariantSourceUndefined:
		return "<undefined>"
	case fwVariantSourceDB:
		return "in-DB-cache"
	case fwVariantSourceSysfs:
		return "sysfs"
	case fwVariantSourceImage:
		return "image"
	case fwVariantSourceUser:
		return "user-input"
	}
	return fmt.Sprintf("<unknown_%d>", src)
}

type fwVariantSources []fwVariantSource

func (s fwVariantSources) String() string {
	str := make([]string, 0, len(s))
	for _, src := range s {
		str = append(str, src.String())
	}
	return strings.Join(str, ",")
}

func detectLocalFirmware(log logger.Logger, manifoldEntry *afas.FirmwareImageMetadata, imageBytes []byte) []firmwareVariant {
	// originalFirmwareVariants is a map of "firmware version and
	// release date required to try to find the original firmware image" to
	// "list of sources where this variant was proposed from".
	//
	// There are few ways to detect which firmware version/date it is:
	// * Try to find a similar firmware in the collection of previously
	//   checked firmwares. It already has information about the version.
	// * Read from the SMBIOS static data module of the image.
	// * Read from DMI table available through sysfs.
	//
	// And each way is not reliable enough, so we try all of them until
	// the original image will be found, so we collect variants into
	// originalFirmwareVariants, and then performing a request for
	// each variant until success.
	//
	// Reliability problems:
	// * The version parsed directly from SMBIOS section of the firmware
	//   may contain invalid data. Sometimes ODMs places incorrect data
	//   to the section and then use a separate EXE-file to fix the data
	//   while a boot process.
	// * The version extracted from DMI might be incorrect because it
	//   contains the version of the booted firmware, while in the
	//   firmware upgrade flow we dump a firmware (after flashing it)
	//   without reboot.
	// * The version stored in Manifold could be incorrect due to old errors
	//   in AFAS or due to wrong version reported by methods above.
	originalFirmwareVariants := map[firmwareVariant]fwVariantSources{}

	if manifoldEntry != nil && manifoldEntry.Version != nil && manifoldEntry.ReleaseDate != nil {
		variant := firmwareVariant{
			Version:     *manifoldEntry.Version,
			ReleaseDate: *manifoldEntry.ReleaseDate,
		}
		originalFirmwareVariants[variant] = append(originalFirmwareVariants[variant], fwVariantSourceDB)
	}

	for sourceName, factory := range map[fwVariantSource]func() (*dmidecode.DMITable, error){
		fwVariantSourceImage: func() (*dmidecode.DMITable, error) {
			return dmidecode.DMITableFromFirmwareImage(imageBytes)
		},
		fwVariantSourceSysfs: func() (*dmidecode.DMITable, error) {
			return dmidecode.LocalDMITable()
		},
	} {
		log.Debugf("trying source %s", sourceName)
		dmiTable, err := factory()
		log.Debugf("source %s result: %p %v", sourceName, dmiTable, err)
		if dmiTable == nil {
			log.Debugf("unable to parse SMBIOS data from %s: %v", sourceName, err)
			continue
		}

		biosInfo := dmiTable.BIOSInfo()
		// See also the comment of originalFirmwareVariants
		variant := firmwareVariant{
			Version:     biosInfo.Version,
			ReleaseDate: biosInfo.ReleaseDate,
		}
		originalFirmwareVariants[variant] = append(originalFirmwareVariants[variant], sourceName)

		trimmedVersion := strings.TrimSpace(biosInfo.Version)
		if trimmedVersion != biosInfo.Version {
			log.Debugf("adding version string with space trimmed %s", trimmedVersion)
			variant = firmwareVariant{
				Version:     trimmedVersion,
				ReleaseDate: biosInfo.ReleaseDate,
			}
			originalFirmwareVariants[variant] = append(originalFirmwareVariants[variant], sourceName)
		}
	}

	// Since all firmware detection methods are unreliable (see description of
	// originalFirmwareVariants) we prefer the most frequent answer.
	//
	// For example it is highly unlikely to get DMI table and parsed SMBIOS have
	// the same but invalid value.
	//
	// Therefore we sorting the variants by their occurrence count. But if
	// variants have the same occurrence count then we prefer more reliable
	// methods (and we prefer DB over parsed SMBIOS, and parsed SMBIOS over
	// extracted DMI table from sysfs).
	for _, s := range originalFirmwareVariants {
		sort.Slice(s, func(i, j int) bool {
			return s[i] < s[j]
		})
	}
	originalFirmwareVariantsOrdered := make([]firmwareVariant, 0, len(originalFirmwareVariants))
	for variant := range originalFirmwareVariants {
		originalFirmwareVariantsOrdered = append(originalFirmwareVariantsOrdered, variant)
	}
	sort.Slice(originalFirmwareVariantsOrdered, func(i, j int) bool {
		a := originalFirmwareVariants[originalFirmwareVariantsOrdered[i]]
		b := originalFirmwareVariants[originalFirmwareVariantsOrdered[j]]

		// Sort by occurrence count
		if len(a) != len(b) {
			return len(a) > len(b)
		}

		// Sort by method
		return a[0] < b[0]
	})
	for _, variant := range originalFirmwareVariantsOrdered[1:] {
		// Here we get all non-primary variants (see "[:1]" in "range originalFirmwareVariantsOrdered[1:]"),
		// and print them.
		log.WithFields(field.Map[string]{
			"firmware_version_pre": originalFirmwareVariantsOrdered[0].Version,
			"firmware_date_pre":    originalFirmwareVariantsOrdered[0].ReleaseDate,
		}).Warnf("the firmware version and date provided by %s (%s,%s) does not match provided by %s (%s,%s)",
			originalFirmwareVariants[variant],
			variant.Version, variant.ReleaseDate,
			originalFirmwareVariants[originalFirmwareVariantsOrdered[0]],
			originalFirmwareVariantsOrdered[0].Version, originalFirmwareVariantsOrdered[0].ReleaseDate,
		)
	}
	return originalFirmwareVariantsOrdered
}

func localHostInfo() (*afas.HostInfo, error) {
	var hostInfo afas.HostInfo
	hostInfo.IsClientHostAnalyzed = true

	hostname, err := os.Hostname()
	if err != nil {
		return nil, ErrDetectHostname{Err: err}
	}
	hostInfo.Hostname = &hostname

	dmiTable, _ := dmidecode.LocalDMITable()
	if dmiTable != nil {
		sn := dmiTable.SystemInfo().SystemSerialNumber
		hostInfo.SerialNumber = &sn
	}

	return &hostInfo, nil
}

package rtpdb

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb/models"
)

// Filter defines conditions to select firmware entries
type Filter interface {
	// WhereCond returns an SQL substring for "WHERE" with placeholders for
	// arguments (if required) and the arguments.
	//
	// A result of a query using WhereCond may contain extra values, due
	// to inability to perform effective fine filtering on SQL level, thus
	// use function Match to do the actual filtering after fetching the
	// entries from an RDBMS.
	WhereCond() (string, []interface{})

	// Match returns true if the firmware satisfies the filter conditions.
	Match(*Firmware) bool
}

// FilterVersion defines a firmware version condition to select firmwares.
type FilterVersion string

// WhereCond implements Filter.
func (f FilterVersion) WhereCond() (string, []interface{}) {
	return "`fw_version` = ?", []interface{}{string(f)}
}

// Match implements Filter.
func (f FilterVersion) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	return fw.Version == string(f)
}

// FilterTypes defines a firmware types condition to select firmwares.
type FilterTypes []models.FirmwareType

// WhereCond implements Filter.
func (f FilterTypes) WhereCond() (string, []interface{}) {
	if len(f) == 0 {
		return "1 == 0", nil
	}
	s := make([]string, 0, len(f))
	for _, t := range f {
		s = append(s, t.String())
	}
	return fmt.Sprintf("type IN (%s)", strings.Join(s, ",")), nil
}

// Match implements Filter.
func (f FilterTypes) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, t := range f {
		if fw.Type == t {
			return true
		}
	}
	return false
}

// FilterNot inverts conditions. If any of the nested filters are satisfied,
// then FilterNot result is "not satisfied".
type FilterNot []Filter

// WhereCond implements Filter.
func (f FilterNot) WhereCond() (string, []interface{}) {
	whereCond, args := Filters(f).joinWhereConds("OR")
	return "NOT (" + whereCond + ")", args
}

// Match implements Filter.
func (f FilterNot) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, filter := range f {
		if filter.Match(fw) {
			return false
		}
	}
	return true
}

// FiltersOR combines internal filter using OR
type FiltersOR []Filter

// WhereCond implements Filter.
func (f FiltersOR) WhereCond() (string, []interface{}) {
	whereCond, args := Filters(f).joinWhereConds("OR")
	return "(" + whereCond + ")", args
}

// Match implements Filter.
func (f FiltersOR) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, filter := range f {
		if filter.Match(fw) {
			return true
		}
	}
	return false
}

// FilterPCR0Tag filters only the entries which are associated with a measurement with a specified metadata value.
type FilterMeasurementMetadata struct {
	Key   string
	Value string
}

// WhereCond implements Filter.
func (f FilterMeasurementMetadata) WhereCond() (string, []any) {
	return "firmware_measurement_type_metadata.key = ? AND firmware_measurement_type_metadata.value = ?", []any{f.Key, f.Value}
}

// Match implements Filter.
func (f FilterMeasurementMetadata) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}

	for _, m := range fw.Measurements {
		for _, metadata := range m.FirmwareMeasurementType.Metadata {
			if metadata.Key == f.Key {
				return metadata.Value == f.Value
			}
		}
	}

	return false
}

// FilterIDs filters only the entries with the specified IDs.
type FilterIDs []int64

// WhereCond implements Filter.
func (f FilterIDs) WhereCond() (string, []interface{}) {
	if len(f) == 0 {
		return "1 == 0", nil
	}
	s := make([]string, 0, len(f))
	for _, id := range f {
		s = append(s, strconv.FormatInt(id, 10))
	}
	return fmt.Sprintf("id IN (%s)", strings.Join(s, ",")), nil
}

// Match implements Filter.
func (f FilterIDs) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, id := range f {
		if fw.ID == id {
			return true
		}
	}
	return false
}

// FilterModelFamilyIDs filters only the entries with the specified model family IDs.
type FilterModelIDs []uint64

// WhereCond implements Filter.
func (f FilterModelIDs) WhereCond() (string, []interface{}) {
	if len(f) == 0 {
		return "1 == 0", nil
	}
	s := make([]string, 0, len(f))
	for _, id := range f {
		s = append(s, strconv.FormatUint(id, 10))
	}
	return fmt.Sprintf("firmware_targets.model_id IN (%s)", strings.Join(s, ",")), nil
}

// Match implements Filter.
func (f FilterModelIDs) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}

	m := map[int64]struct{}{}
	for _, id := range f {
		m[int64(id)] = struct{}{}
	}

	for _, target := range fw.Targets {
		if target.ModelID == nil {
			continue
		}
		modelID := *target.ModelID

		if _, ok := m[modelID]; ok {
			return true
		}
	}
	return false
}

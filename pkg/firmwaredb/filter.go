package rtpdb

import (
	"fmt"
	"strconv"
	"strings"

	"privatecore/firmware/analyzer/if/rtp"
	"privatecore/firmware/analyzer/pkg/rtpdb/models"
	"privatecore/firmware/analyzer/pkg/types"
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
	return fw.FWVersion == string(f)
}

// FilterTypes defines a firmware types condition to select firmwares.
type FilterTypes []models.FirmwareType

// WhereCond implements Filter.
func (f FilterTypes) WhereCond() (string, []interface{}) {
	if len(f) == 0 {
		return "1 == 0", nil
	}
	s := make([]string, 0, len(f))
	for _, _type := range f {
		s = append(s, strconv.FormatInt(int64(_type), 10))
	}
	return fmt.Sprintf("firmware_type IN (%s)", strings.Join(s, ",")), nil
}

// Match implements Filter.
func (f FilterTypes) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, t := range f {
		if fw.FirmwareType == t {
			return true
		}
	}
	return false
}

// FilterEvaluationStatus defines an evaluation status condition to select firmwares.
type FilterEvaluationStatus EvaluationStatus

// WhereCond implements Filter.
func (f FilterEvaluationStatus) WhereCond() (string, []interface{}) {
	return "evaluation_status = ?", []interface{}{int64(f)}
}

// Match implements Filter.
func (f FilterEvaluationStatus) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	return fw.EvaluationStatus == EvaluationStatus(f)
}

// FilterQualificationStatuses defines a qualification statuses condition to select firmwares.
type FilterQualificationStatuses []QualificationStatus

// WhereCond implements Filter.
func (f FilterQualificationStatuses) WhereCond() (string, []interface{}) {
	if len(f) == 0 {
		return "1 == 0", nil
	}
	s := make([]string, 0, len(f))
	for _, status := range f {
		s = append(s, strconv.FormatInt(int64(status), 10))
	}
	return fmt.Sprintf("qualification_status IN (%s)", strings.Join(s, ",")), nil
}

// Match implements Filter.
func (f FilterQualificationStatuses) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, status := range f {
		if rtp.QualificationStatus(fw.QualificationStatus) == status {
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

// FilterPCR0Tag filters only the entries which contains a PCR0 value with a specified tag.
type FilterPCR0Tag types.TagID

// WhereCond implements Filter.
func (f FilterPCR0Tag) WhereCond() (string, []interface{}) {
	return "fw_hash LIKE ?", []interface{}{fmt.Sprintf("%%i:%d;%%", f)}
}

// Match implements Filter.
func (f FilterPCR0Tag) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	hashes, _ := models.UnmarshalFirmwareHash(fw.FWHash)
	for _, hash := range hashes {
		for _, tag := range hash.Tags {
			if tag == types.TagID(f) {
				return true
			}
		}
	}
	return false
}

// FilterFilenames filters only the entries with the specified tar filenames.
type FilterFilenames []string

// WhereCond implements Filter.
func (f FilterFilenames) WhereCond() (string, []interface{}) {
	if len(f) == 0 {
		return "1 == 0", nil
	}
	return "filename IN (?)", []interface{}{strings.Join(f, ",")}
}

// Match implements Filter.
func (f FilterFilenames) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, filename := range f {
		if fw.Filename == filename {
			return true
		}
	}
	return false
}

// FilterIDs filters only the entries with the specified IDs.
type FilterIDs []uint64

// WhereCond implements Filter.
func (f FilterIDs) WhereCond() (string, []interface{}) {
	if len(f) == 0 {
		return "1 == 0", nil
	}
	s := make([]string, 0, len(f))
	for _, id := range f {
		s = append(s, strconv.FormatUint(id, 10))
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
type FilterModelFamilyIDs []uint64

// WhereCond implements Filter.
func (f FilterModelFamilyIDs) WhereCond() (string, []interface{}) {
	if len(f) == 0 {
		return "1 == 0", nil
	}
	s := make([]string, 0, len(f))
	for _, id := range f {
		s = append(s, strconv.FormatUint(id, 10))
	}
	return fmt.Sprintf("model_family_id IN (%s)", strings.Join(s, ",")), nil
}

// Match implements Filter.
func (f FilterModelFamilyIDs) Match(fw *Firmware) bool {
	if fw == nil {
		return false
	}
	for _, id := range f {
		if fw.ModelFamilyID == nil {
			continue
		}
		if *fw.ModelFamilyID == id {
			return true
		}
	}
	return false
}

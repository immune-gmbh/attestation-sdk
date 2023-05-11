package analysis

import (
	"fmt"
	"strings"
)

func init() {
	RegisterType((*ErrAnalyze)(nil))
	RegisterType((*ErrNotApplicable)(nil))
	RegisterType((*ErrFailedCalcInput)(nil))
	RegisterType((*ErrResolveInput)(nil))
	RegisterType((*ErrResolveValue)(nil))
}

// ErrNotApplicable should be returned by analyzer to tell that it is not applicable for given input
type ErrNotApplicable struct {
	Description string
}

func (e ErrNotApplicable) Error() string {
	return fmt.Sprintf("not applicable: %s", e.Description)
}

// NewErrNotApplicable creates a new ErrNotApplicable object
func NewErrNotApplicable(description string) ErrNotApplicable {
	return ErrNotApplicable{Description: description}
}

// ErrMissingInput determines situation when input needed by analyzer is missing
type ErrMissingInput struct {
	providedInput Input
	missingType   string
}

func (e ErrMissingInput) Error() string {
	r := fmt.Sprintf("Missing input '%s'; provided input: %s", e.missingType, e.providedInput)
	if len(r) <= 4096 {
		return r
	}

	var typeIDs []string
	for _typeID := range e.providedInput {
		typeIDs = append(typeIDs, string(_typeID))
	}
	return fmt.Sprintf("Missing input '%s'; provided types in the input: %s", e.missingType, strings.Join(typeIDs, ", "))
}

// ErrCalcNotSupported determines a situation when input data calculator doesn't support the type
type ErrCalcNotSupported struct {
	typeName string
}

func (e ErrCalcNotSupported) Error() string {
	return fmt.Sprintf("type %s calculation is not supported", e.typeName)
}

// ErrFailedCalcInput determines a situation when input value should be calculated and that calculation failed
type ErrFailedCalcInput struct {
	Input string
	Err   error
}

func (e ErrFailedCalcInput) Error() string {
	return fmt.Sprintf("Failed to calc input '%s': '%v'", e.Input, e.Err)
}

func (e ErrFailedCalcInput) Unwrap() error {
	return e.Err
}

// ErrResolveValue means it was unable to resolve a value, required by the analyzer.
type ErrResolveValue struct {
	FieldName string
	TypeName  string
	Err       error
}

// Error implements interface "error".
func (e ErrResolveValue) Error() string {
	return fmt.Sprintf("unable to resolve value of field '%s' (%s): %v", e.FieldName, e.TypeName, e.Err)
}

// Unwrap is used by errors.Is and errors.As.
func (e ErrResolveValue) Unwrap() error {
	return e.Err
}

// ErrResolveInput means it was unable to resolve input, required by the analyzer.
type ErrResolveInput struct {
	Err error
}

// Error implements interface "error".
func (e ErrResolveInput) Error() string {
	return fmt.Sprintf("unable to resolve input: %v", e.Err)
}

// Unwrap is used by errors.Is and errors.As.
func (e ErrResolveInput) Unwrap() error {
	return e.Err
}

// ErrAnalyze means got an error from calling Analyze().
type ErrAnalyze struct {
	Err error
}

// Error implements interface "error".
func (e ErrAnalyze) Error() string {
	return fmt.Sprintf("Analyze() error: %v", e.Err)
}

// Unwrap is used by errors.Is and errors.As.
func (e ErrAnalyze) Unwrap() error {
	return e.Err
}

// ErrTypeIDNotRegistered means there was an attempt to serialize/deserialize a value
// of a type, not registered in the type register (see also function `RegisterType`).
type ErrTypeIDNotRegistered struct {
	TypeID TypeID
}

// Error implements interface "error".
func (e ErrTypeIDNotRegistered) Error() string {
	return fmt.Sprintf("type with TypeID '%s' is not registered", e.TypeID)
}

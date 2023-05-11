package imgalign

import (
	"fmt"
)

// ErrNoOrigImageToCompareWith is returned on attempt to make a diff
// report if nil original image.
type ErrNoOrigImageToCompareWith struct{}

func (ErrNoOrigImageToCompareWith) Error() string {
	return "no original image to compare with"
}

// ErrImageLengthDoesNotMatch is returned when the size of the UEFI image
// is not as expected.
type ErrImageLengthDoesNotMatch struct {
	ExpectedLength uint
	ReceivedLength uint
}

func (err ErrImageLengthDoesNotMatch) Error() string {
	return fmt.Sprintf("images length does not match: %d != %d", err.ReceivedLength, err.ExpectedLength)
}

// ErrUnableToFindBIOSRegion is returned if BIOSRegion is not found
type ErrUnableToFindBIOSRegion struct {
	Err error
}

func (err ErrUnableToFindBIOSRegion) Error() string {
	return fmt.Sprintf("unable to find BIOS region: %v", err.Err)
}

func (err ErrUnableToFindBIOSRegion) Unwrap() error {
	return err.Err
}

// ErrUnexpectedAmountOfBIOSRegions is returned when an UEFI image
// contains an amount of BIOS regions not equals to one.
type ErrUnexpectedAmountOfBIOSRegions struct {
	FoundCount uint
}

func (err ErrUnexpectedAmountOfBIOSRegions) Error() string {
	return fmt.Sprintf("expected amount of BIOS regions is one, but found: %d", err.FoundCount)
}

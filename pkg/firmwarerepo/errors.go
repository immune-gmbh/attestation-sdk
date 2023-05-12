package firmwarerepo

import (
	"fmt"
)

// ErrHTTPGet implements "error", for the description see Error.
type ErrHTTPGet struct {
	Err error
	URL string
}

func (err ErrHTTPGet) Error() string {
	return fmt.Sprintf("unable to GET a HTTP resource '%s': %v",
		err.URL, err.Err)
}

func (err ErrHTTPGet) Unwrap() error {
	return err.Err
}

// ErrHTTPGetBody implements "error", for the description see Error.
type ErrHTTPGetBody struct {
	Err error
	URL string
}

func (err ErrHTTPGetBody) Error() string {
	return fmt.Sprintf("unable to read body of HTTP GET-resource '%s': %v",
		err.URL, err.Err)
}

func (err ErrHTTPGetBody) Unwrap() error {
	return err.Err
}

// ErrUnknownFirmwareImage represents situation when firmware image has unknown format
type ErrUnknownFirmwareImage struct {
}

func (err ErrUnknownFirmwareImage) Error() string {
	return "unable to parse firmware image"
}

// ErrNoFirmwareFoundInTarGZ implements "error", for the description see Error.
type ErrNoFirmwareFoundInTarGZ struct {
}

func (err ErrNoFirmwareFoundInTarGZ) Error() string {
	return "nothing in the tar.gz looks like a firmware image"
}

// ErrGetMeta implements "error", for the description see Error.
type ErrGetMeta struct {
	Err error
}

func (err ErrGetMeta) Error() string {
	return fmt.Sprintf("unable to get the metadata record: %v", err.Err)
}

func (err ErrGetMeta) Unwrap() error {
	return err.Err
}

// ErrHTTPMakeRequest implements "error", for the description see Error.
type ErrHTTPMakeRequest struct {
	Err error
	URL string
}

func (err ErrHTTPMakeRequest) Error() string {
	return fmt.Sprintf("unable to make an HTTP request to '%s': %v", err.URL, err.Err)
}

func (err ErrHTTPMakeRequest) Unwrap() error {
	return err.Err
}

// ErrParseURL implements "error", for the description see Error.
type ErrParseURL struct {
	Err error
	URL string
}

func (err ErrParseURL) Error() string {
	return fmt.Sprintf("unable to parse '%s' as URL: %v", err.URL, err.Err)
}

func (err ErrParseURL) Unwrap() error {
	return err.Err
}

// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

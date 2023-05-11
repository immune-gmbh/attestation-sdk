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
package storage

import (
	"fmt"

	"github.com/go-sql-driver/mysql"
)

// ErrInitMySQL implements "error", for the description see Error.
type ErrInitMySQL struct {
	Err error
	DSN string
}

func (err ErrInitMySQL) Error() string {
	return fmt.Sprintf("unable to initialize a MySQL client (DSN: '%s'): %v", err.DSN, err.Err)
}

func (err ErrInitMySQL) Unwrap() error {
	return err.Err
}

// ErrMySQLPing implements "error", for the description see Error.
type ErrMySQLPing struct {
	Err error
}

func (err ErrMySQLPing) Error() string {
	return fmt.Sprintf("unable to ping the MySQL server: %v", err.Err)
}

func (err ErrMySQLPing) Unwrap() error {
	return err.Err
}

// ErrUnableToUpload implements "error", for the description see Error.
type ErrUnableToUpload struct {
	Key []byte
	Err error
}

func (err ErrUnableToUpload) Error() string {
	return fmt.Sprintf("unable to upload file '%X': %v", err.Key, err.Err)
}

func (err ErrUnableToUpload) Unwrap() error {
	return err.Err
}

// ErrUnableToUpdate implements "error", for the description see Error.
type ErrUnableToUpdate struct {
	insertedValue string
	Err           error
}

func (err ErrUnableToUpdate) Error() string {
	return fmt.Sprintf("unable to insert '%s' to the metadata table: %v",
		err.insertedValue, err.Err)
}

func (err ErrUnableToUpdate) Unwrap() error {
	return err.Err
}

// ErrUnableToInsert implements "error", for the description see Error.
type ErrUnableToInsert struct {
	insertedValue string
	Err           error
}

func (err ErrUnableToInsert) Error() string {
	return fmt.Sprintf("unable to insert '%s' to the metadata table: %v",
		err.insertedValue, err.Err)
}

func (err ErrUnableToInsert) Unwrap() error {
	return err.Err
}

// ErrAlreadyExists implements "error", for the description see Error.
type ErrAlreadyExists struct {
	insertedValue string
	Err           *mysql.MySQLError
}

func (err ErrAlreadyExists) Error() string {
	return fmt.Sprintf("image '%s' is already inserted to the metadata table: %v",
		err.insertedValue, err.Err)
}

func (err ErrAlreadyExists) Unwrap() error {
	return err.Err
}

// ErrUnableToUpdateMetadata implements "error", for the description see Error.
type ErrUnableToUpdateMetadata struct {
	Err error
}

func (err ErrUnableToUpdateMetadata) Error() string {
	return fmt.Sprintf("unable to update metadata record: %v", err.Err)
}

func (err ErrUnableToUpdateMetadata) Unwrap() error {
	return err.Err
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

// ErrGetData implements "error", for the description see Error.
type ErrGetData struct {
	Err error
}

func (err ErrGetData) Error() string {
	return fmt.Sprintf("unable to get the data: %v", err.Err)
}

func (err ErrGetData) Unwrap() error {
	return err.Err
}

// ErrSelect implements "error", for the description see Error.
type ErrSelect struct {
	Err error
}

func (err ErrSelect) Error() string {
	return fmt.Sprintf("unable to select rows from MySQL: %v", err.Err)
}

func (err ErrSelect) Unwrap() error {
	return err.Err
}

// ErrNotFound implements "error", for the description see Error.
type ErrNotFound struct {
	Query string
}

func (err ErrNotFound) Error() string {
	return fmt.Sprintf("not found (query: %s)", err.Query)
}

// ErrTooManyEntries implements "error", for the description see Error.
type ErrTooManyEntries struct {
	Count uint
}

func (err ErrTooManyEntries) Error() string {
	return fmt.Sprintf("too many entries: %d", err.Count)
}

// ErrDownload implements "error", for the description see Error.
type ErrDownload struct {
	Err error
}

func (err ErrDownload) Error() string {
	return fmt.Sprintf("unable to download: %v", err.Err)
}

func (err ErrDownload) Unwrap() error {
	return err.Err
}

// ErrEmptyFilters signals that search filters are empty and effectively
// the request requires to select all the data, which is forbidden.
type ErrEmptyFilters struct{}

func (err ErrEmptyFilters) Error() string {
	return "empty filters"
}

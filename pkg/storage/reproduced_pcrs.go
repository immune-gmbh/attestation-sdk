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
	"context"
	"fmt"
	"strings"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/helpers"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/jmoiron/sqlx"
)

// FindReproducedPCRsOne returns reproduced single PCRs item by unique search key
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//
//	management of metadata in MySQL and data in BlobStorage for firmware images. All the rest
//	entities should not be accessed through Storage. Otherwise locking, transactions and other
//	usual stuff is pretty cludgy.
func (stor *Storage) FindReproducedPCRsOne(ctx context.Context, key models.UniqueKey) (models.ReproducedPCRs, error) {
	_, columns, err := helpers.GetValuesAndColumns(&models.ReproducedPCRs{}, nil)
	if err != nil {
		return models.ReproducedPCRs{}, err
	}

	var result []models.ReproducedPCRs
	query := fmt.Sprintf(
		"SELECT %s FROM `reproduced_pcrs` WHERE `hash_stable` = ? AND `registers_sha512` = ? AND `tpm_device` = ?",
		strings.Join(columns, ","),
	)
	if err := sqlx.Select(stor.DB, &result, query, key.HashStable, key.RegistersSHA512, key.TPMDevice); err != nil {
		return models.ReproducedPCRs{}, fmt.Errorf("unable to query firmware metadata: %w", err)
	}
	if len(result) == 0 {
		return models.ReproducedPCRs{}, ErrNotFound{Query: query}
	}
	if len(result) > 1 {
		panic(fmt.Errorf("unexpectedly high number of affected rows: '%d'", len(result)))
	}
	return result[0], nil
}

// SelectReproducedPCRs selects all reproduced PCR values
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//
//	management of metadata in MySQL and data in BlobStorage for firmware images. All the rest
//	entities should not be accessed through Storage. Otherwise locking, transactions and other
//	usual stuff is pretty cludgy.
func (stor *Storage) SelectReproducedPCRs(ctx context.Context) ([]models.ReproducedPCRs, error) {
	_, columns, err := helpers.GetValuesAndColumns(&models.ReproducedPCRs{}, nil)
	if err != nil {
		return nil, err
	}

	var result []models.ReproducedPCRs
	query := fmt.Sprintf(
		"SELECT %s FROM `reproduced_pcrs`",
		strings.Join(columns, ","),
	)
	if err := sqlx.Select(stor.DB, &result, query); err != nil {
		return nil, fmt.Errorf("unable to query firmware metadata: %w", err)
	}
	return result, nil
}

func ptr[T any](v T) *T {
	return &v
}

// SelectReproducedPCRsWithImageMetadata selects an INNER JOIN of reproduced PCRs with image metadatas.
// The indexes of both returned slices corresponds to each other.
//
// TODO: Remove these functions from `Storage`. The initial purpose of storage is combine together
//
//	management of metadata in MySQL and data in BlobStorage for firmware images. All the rest
//	entities should not be accessed through Storage. Otherwise locking, transactions and other
//	usual stuff is pretty cludgy.
func (stor *Storage) SelectReproducedPCRsWithImageMetadata(ctx context.Context) ([]models.ReproducedPCRs, []models.FirmwareImageMetadata, error) {
	var (
		leftRow  models.ReproducedPCRs
		rightRow models.FirmwareImageMetadata
	)
	leftValues, leftColumns, err := helpers.GetValuesAndColumns(&leftRow, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get column for the table of reproduced PCRs")
	}
	rightValues, rightColumns, err := helpers.GetValuesAndColumns(&rightRow, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get column for the table of image metadata")
	}

	query := fmt.Sprintf(
		"SELECT %s,%s FROM `reproduced_pcrs` `pcrs` JOIN `firmware_image_metadata` `meta` ON `pcrs`.`hash_stable` = `meta`.`hash_stable`",
		constructColumns("pcrs", leftColumns),
		constructColumns("meta", rightColumns),
	)
	rows, err := stor.DB.Query(query)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to query '%s': %w", query, err)
	}
	defer rows.Close()

	var (
		leftResult  []models.ReproducedPCRs
		rightResult []models.FirmwareImageMetadata
	)

	allValues := append(append([]any{}, leftValues...), rightValues...)
	for rows.Next() {
		rightRow.ImageID = types.ImageID{}
		err := rows.Scan(allValues...)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to scan values: %w (query: '%s')", err, query)
		}
		leftResult = append(leftResult, leftRow)
		rightResult = append(rightResult, rightRow)
	}

	return leftResult, rightResult, nil
}

// UpsertReproducedPCRs inserts ReproducedPCRs or updates reproduced pcr values if item already exists structure
func (stor *Storage) UpsertReproducedPCRs(ctx context.Context, reproducedPCRs models.ReproducedPCRs) error {
	values, columns, err := helpers.GetValuesAndColumns(&reproducedPCRs, func(fieldName string, value any) bool {
		return fieldName == "ID"
	})
	if err != nil {
		return fmt.Errorf("failed to parse reproducedPCRs: '%w'", err)
	}

	columnsStr := "`" + strings.Join(columns, "`,`") + "`"
	placeholders := constructPlaceholders(len(columns))

	_, err = stor.DB.Exec("INSERT INTO `reproduced_pcrs` ("+columnsStr+") VALUES ("+placeholders+")", values...)
	if err == nil {
		return nil
	}
	if asMySQLError(err, 1062) != nil {
		// already inserted -> update pcr0 value
		res, err := stor.DB.Exec(
			"UPDATE `reproduced_pcrs` SET `pcr0_sha1` = ?, `pcr0_sha256` = ? WHERE `hash_stable` = ? AND `registers_sha512` = ? AND `tpm_device` = ?",
			reproducedPCRs.PCR0SHA1,
			reproducedPCRs.PCR0SHA256,
			reproducedPCRs.HashStable,
			reproducedPCRs.RegistersSHA512,
			reproducedPCRs.TPMDevice,
		)
		if err != nil {
			return ErrUnableToUpdate{insertedValue: fmt.Sprintf("%v", reproducedPCRs), Err: fmt.Errorf("failed to determine the number of affected rows: %w", err)}
		}

		cnt, err := res.RowsAffected()
		if err != nil {
			return ErrUnableToUpdate{insertedValue: fmt.Sprintf("%v", reproducedPCRs), Err: fmt.Errorf("failed to determine the number of affected rows: %w", err)}
		}

		if cnt > 1 {
			// we should update no more than a single item, because rowID is a primary key
			panic(fmt.Sprintf("unexpectedly high number of affected rows: '%d'", cnt))
		}
		return nil
	}

	return mySQLInsertError(fmt.Sprintf("%v", reproducedPCRs), fmt.Errorf("unable to insert the row: %w", err))
}

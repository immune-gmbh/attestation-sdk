package firmwaredb

import (
	"context"
	"fmt"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/jmoiron/sqlx"
)

type DB struct {
	ConnectionString string
}

func New(connectionString string) *DB {
	return &DB{
		ConnectionString: connectionString,
	}
}

func (db *DB) Get(ctx context.Context, filters ...Filter) ([]*Firmware, error) {
	whereCond, args := Filters(filters).WhereCond()

	query := "SELECT * FROM `firmware` WHERE " + whereCond
	logger.FromCtx(ctx).Debugf("query:'%s', args:%v", query, args)

}

// GetFirmwares returns firmware metadata according to the filters.
func GetFirmwares(ctx context.Context, db Querier, filters ...Filter) ([]Firmware, error) {
	logger := logger.FromCtx(ctx)
	logger.Debugf("whereCond:'%s', args:%v", whereCond, args)

	query := "SELECT * FROM `firmware` WHERE " + whereCond
	var preFiltered []Firmware
	err := sqlx.SelectContext(ctx, db, &preFiltered, query, args...)
	if err != nil {
		return nil, fmt.Errorf("unable to query firmware metadata using query '%s' with arguments %v: %w", query, args, err)
	}

	// If it was impossible to effectively filter something using SQL WHERE condition,
	// where do post filtering here:
	var filtered []Firmware
	for _, fw := range preFiltered {
		if !Filters(filters).Match(&fw) {
			logger.Debugf("entry %d:%s:%s was filtered out", fw.ID, fw.FWVersion, fw.GetDate())
			continue
		}
		logger.Debugf("entry %d:%s:%s matches, adding", fw.ID, fw.FWVersion, fw.GetDate())
		filtered = append(filtered, fw)
	}

	return filtered, nil
}

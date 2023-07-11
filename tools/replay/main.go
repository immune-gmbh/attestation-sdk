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
package main

import (
	"context"
	"database/sql"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/immune-gmbh/attestation-sdk/cmd/afascli/commands/analyze/format"
	"github.com/immune-gmbh/attestation-sdk/if/typeconv"
	"github.com/immune-gmbh/attestation-sdk/pkg/observability"
	"github.com/immune-gmbh/attestation-sdk/pkg/storage/models"
	"github.com/immune-gmbh/attestation-sdk/pkg/types"
	"github.com/immune-gmbh/attestation-sdk/tools/replay/replay"

	"github.com/facebookincubator/go-belt/beltctx"
	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
	"github.com/facebookincubator/go-belt/tool/logger"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
	"github.com/spf13/pflag"
)

func assertNoError(ctx context.Context, err error) {
	if err != nil {
		logger.FromCtx(ctx).Fatalf("%v", err)
	}
}

func usageExit() {
	pflag.Usage()
	os.Exit(2) // The default Go's exitcode on flag.Parse() problems
}

func main() {
	logLevel := logger.LevelInfo // the default value
	defaultDSN := (&mysql.Config{
		User:      os.Getenv("DBUSER"),
		Passwd:    os.Getenv("DBPASS"),
		Net:       "tcp",
		Addr:      "127.0.0.1:3306",
		DBName:    "afas",
		ParseTime: true,
	}).FormatDSN()

	rdbmsDriver := pflag.String("rdbms-driver", "mysql", "")
	rdbmsDSN := pflag.String("rdbms-dsn", defaultDSN, "")
	blobstorageURL := pflag.String("object-storage-url", `fs:///srv/afasd`, "URL to an object storage where the firmware images are stored")
	analyzerReportID := pflag.Int64("analyzer-report-id", 0, "")
	pflag.Parse()

	ctx := observability.WithBelt(
		context.Background(),
		logLevel,
		"AFAS-replay", true,
	)

	defer func() {
		// We want:
		// * Observe panics and report about them (for example to Scuba).
		// * Make sure that everything reported through Logger/ErrorMonitor/whatnot
		//   was really sent out, before we exit the application (and thus beltctx.Flush).
		if event := errmon.ObserveRecoverCtx(ctx, recover()); event != nil {
			beltctx.Flush(ctx)
			panic(event.PanicValue)
		}

		beltctx.Flush(ctx)
	}()

	if pflag.NArg() != 0 {
		usageExit()
	}
	if *analyzerReportID == 0 {
		logger.FromCtx(ctx).Fatalf("-analyzer-report-id is required")
	}

	fianoLog.DefaultLogger = newFianoLogger(logger.FromCtx(ctx).WithField("module", "fiano"))

	report, err := replay.AnalyzerReport(ctx, *blobstorageURL, *rdbmsDriver, *rdbmsDSN, *analyzerReportID)
	assertNoError(ctx, err)

	format.HumanReadable(os.Stdout, *typeconv.ToThriftAnalyzeReport(&models.AnalyzeReport{
		ID:              0,
		JobID:           types.JobID{},
		AssetID:         nil,
		Timestamp:       time.Now(),
		ProcessedAt:     sql.NullTime{},
		GroupKey:        nil,
		AnalyzerReports: []models.AnalyzerReport{*report},
	}), true, false)
}

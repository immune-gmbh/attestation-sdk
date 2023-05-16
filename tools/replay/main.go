package main

import (
	"context"
	"database/sql"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/cmd/afascli/commands/analyze/format"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/if/typeconv"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage/models"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/tools/replay/replay"

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

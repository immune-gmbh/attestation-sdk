package main

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/analysis"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/blobstorage"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/devicegetter"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwaredb/firmwaredbsql"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/firmwarerepo"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objcache"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/observability"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller"
	controllertypes "github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/controller/types"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/server/thrift"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/storage"

	"github.com/facebookincubator/go-belt/tool/logger"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
	"github.com/spf13/pflag"
)

const (
	diffFirmwareCacheSizeDefault     = 16
	storageCacheSizeDefault          = 1 << 30 // 1GiB
	reportHostConfigCacheSizeDefault = 1000
	rtpfwCacheSizeDefault            = 20
	rtpfwCacheEvictionTimeoutDefault = 24 * time.Hour
	apiCachePurgeTimeoutDefault      = time.Hour
	dataCacheSizeDefault             = 1000
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
		User:   os.Getenv("DBUSER"),
		Passwd: os.Getenv("DBPASS"),
		Net:    "tcp",
		Addr:   "127.0.0.1:3306",
		DBName: "afas",
	}).FormatDSN()

	pflag.Var(&logLevel, "log-level", "logging level")
	netPprofAddr := pflag.String("net-pprof-addr", "", "if non-empty then listens with net/http/pprof")
	thriftBindAddr := pflag.String("thrift-bind-addr", `:17545`, "the address to listen by thrift")
	rdbmsDriverOrigFW := pflag.String("rdbms-driver-fw-orig", "mysql", "")
	rdbmsDSNOrigFW := pflag.String("rdbms-dsn-fw-orig", defaultDSN, "")
	rdbmsDriverInternal := pflag.String("rdbms-driver-internal", "mysql", "")
	rdbmsDSNInternal := pflag.String("rdbms-dsn-internal", defaultDSN, "")
	firmwareImageReportBaseURL := pflag.String("firmware-image-repo-baseurl", "http://localhost/", "")
	objectStorageURL := pflag.String("object-storage-url", "fs:///srv/afasd", "")
	amountOfWorkers := pflag.Uint("workers", uint(runtime.NumCPU()), "amount of concurrent workers")
	workersQueue := pflag.Uint("workers-queue", uint(runtime.NumCPU())*10000, "maximal amount of requests permitted in the queue")
	cpuLoadLimit := pflag.Float64("cpu-load-limit", 0.8, "suspend accepting requests while fraction of busy CPU cycles is more than the specified number")
	apiCachePurgeTimeout := pflag.Duration(
		"api-cache-purge-timeout",
		apiCachePurgeTimeoutDefault,
		"defines API cache purge timeout",
	)
	storageCacheSize := pflag.Uint64("image-storage-cache-size", storageCacheSizeDefault, "defines the memory limit for the storage used to save images, analyzed by AFAS")
	dataCacheSize := pflag.Int("data-cache-size", dataCacheSizeDefault, "defines the size of the cache for internally calculated data objects like parsed firmware, measurements flow")
	pflag.Parse()
	if pflag.NArg() != 0 {
		usageExit()
	}

	ctx := observability.WithBelt(
		context.Background(),
		logLevel,
		"AFAS", true,
	)

	log := logger.FromCtx(ctx)

	if *netPprofAddr != "" {
		go func() {
			err := http.ListenAndServe(*netPprofAddr, nil)
			log.Errorf("unable to start listening for https/net/pprof: %v", err)
		}()
	}

	fianoLog.DefaultLogger = newFianoLogger(log.WithField("module", "fiano"))

	firmwareBlobStorage, err := blobstorage.New(*objectStorageURL)
	if err != nil {
		log.Panic(err)
	}

	firmwareBlobCache, err := objcache.New(*storageCacheSize)
	if err != nil {
		log.Panic(err)
	}

	storage, err := storage.New(*rdbmsDriverInternal, *rdbmsDSNInternal, firmwareBlobStorage, firmwareBlobCache, log)
	if err != nil {
		log.Panic(err)
	}

	origFirmwareDB, err := firmwaredbsql.New(*rdbmsDriverOrigFW, *rdbmsDSNOrigFW)
	if err != nil {
		log.Panic(err)
	}

	origFirmwareRepo := firmwarerepo.New(*firmwareImageReportBaseURL, "FirmwareAnalyzer")

	dataCalculator, err := analysis.NewDataCalculator(*dataCacheSize)
	if err != nil {
		log.Panic(err)
	}
	controllertypes.OverrideValueCalculators(dataCalculator)

	ctrl, err := controller.New(ctx,
		storage,
		origFirmwareDB,
		origFirmwareRepo,
		dataCalculator,
		devicegetter.DummyDeviceGetter{},
		*apiCachePurgeTimeout,
	)
	assertNoError(ctx, err)
	log.Debugf("created a controller")

	srv, err := thrift.NewServer(
		*amountOfWorkers,
		*workersQueue,
		*cpuLoadLimit,
		ctrl,
	)
	assertNoError(ctx, err)
	log.Debugf("created a Thrift server")

	err = srv.Serve(ctx, *thriftBindAddr)
	assertNoError(ctx, err)
}

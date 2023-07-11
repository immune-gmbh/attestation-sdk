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
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/immune-gmbh/attestation-sdk/pkg/analysis"
	"github.com/immune-gmbh/attestation-sdk/pkg/blobstorage"
	"github.com/immune-gmbh/attestation-sdk/pkg/devicegetter"
	"github.com/immune-gmbh/attestation-sdk/pkg/firmwaredb/firmwaredbsql"
	"github.com/immune-gmbh/attestation-sdk/pkg/firmwarerepo"
	"github.com/immune-gmbh/attestation-sdk/pkg/objcache"
	"github.com/immune-gmbh/attestation-sdk/pkg/observability"
	"github.com/immune-gmbh/attestation-sdk/pkg/server/controller"
	controllertypes "github.com/immune-gmbh/attestation-sdk/pkg/server/controller/types"
	"github.com/immune-gmbh/attestation-sdk/pkg/server/thrift"
	"github.com/immune-gmbh/attestation-sdk/pkg/storage"

	"github.com/facebookincubator/go-belt/beltctx"
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
	dbAddr := os.Getenv("DBHOST")
	if dbAddr == "" {
		dbAddr = "127.0.0.1:3306"
	}
	defaultDSN := (&mysql.Config{
		User:      os.Getenv("DBUSER"),
		Passwd:    os.Getenv("DBPASS"),
		Net:       "tcp",
		Addr:      dbAddr,
		DBName:    "afas",
		ParseTime: true,
	}).FormatDSN()

	pflag.Var(&logLevel, "log-level", "logging level")
	netPprofAddr := pflag.String("net-pprof-addr", "", "if non-empty then listens with net/http/pprof")
	thriftBindAddr := pflag.String("thrift-bind-addr", `:17545`, "the address to listen by thrift")
	rdbmsDriverOrigFW := pflag.String("rdbms-driver-fw-orig", "mysql", "")
	rdbmsDSNOrigFW := pflag.String("rdbms-dsn-fw-orig", defaultDSN, "")
	rdbmsDriverInternal := pflag.String("rdbms-driver-internal", "mysql", "")
	rdbmsDSNInternal := pflag.String("rdbms-dsn-internal", defaultDSN, "")
	origFirmwareImageRepoBaseURL := pflag.String("original-firmware-image-repo-baseurl", "http://orig-fw-repo:17546/", "")
	blobStorageURL := pflag.String("blob-storage-url", "fs:///srv/afasd", "")
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

	firmwareBlobStorage, err := blobstorage.New(*blobStorageURL)
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

	origFirmwareRepo := firmwarerepo.New(*origFirmwareImageRepoBaseURL, "AttestationFailureAnalyzer")

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
		beltctx.Belt(ctx),
		logLevel,
	)
	assertNoError(ctx, err)
	log.Debugf("created a Thrift server")

	err = srv.Serve(ctx, *thriftBindAddr)
	assertNoError(ctx, err)
}

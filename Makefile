all: thrift afascli afasd hwsecvalidator

builddir:
	mkdir -p build

thrift:
	rm -rf gen-go
	thrift -r --gen go:package_prefix=github.com/immune-gmbh/AttestationFailureAnalysisService/ if/afas.thrift
	find gen-go -name generated | sed -e 's%gen-go/%%g' -e 's%/generated$$%%g' | xargs -I @ ln -s ../@/generated @/generated

afascli: builddir
	go build -o build/afascli ./cmd/afascli

afasd: builddir
	go build -o build/afasd ./cmd/afasd

hwsecvalidator: builddir
	go build -o build/afasd ./tools/hwsecvalidator

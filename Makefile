all: thrift afascli afasd hwsecvalidator

builddir:
	mkdir -p build

thrift:
	rm -rf gen-go
	find . -type l -name generated -exec rm -f {} +
	thrift -r --gen go:package_prefix=github.com/immune-gmbh/AttestationFailureAnalysisService/ if/afas.thrift
	for GENERATED_PATH in $(shell find gen-go -name generated | sed -e 's%gen-go/%%g' -e 's%/generated$$%%g') ; do \
		ln -s `realpath --relative-to=$${GENERATED_PATH} gen-go/$${GENERATED_PATH}`/generated $${GENERATED_PATH}/generated ; \
	done

afascli: builddir
	go build -o build/afascli ./cmd/afascli

afasd: builddir
	go build -o build/afasd ./cmd/afasd

hwsecvalidator: builddir
	go build -o build/afasd ./tools/hwsecvalidator

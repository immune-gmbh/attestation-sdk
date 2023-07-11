all: docs thrift afascli afasd hwsecvalidator

docs:
	for PLANTUML_FILE in doc/*.plantuml ; do \
		plantuml -png $${PLANTUML_FILE} ; \
	done

builddir:
	mkdir -p build

thrift-cleanup:
	find . -type d -name generated -exec rm -rf {} +

thrift-generate:
	rm -rf ./gen-go
	for THRIFT_FILE in if/afas.thrift if/txt_errors.thrift if/device.thrift doc/v2/if/service.thrift ; do \
		thrift -r --gen go:package_prefix=github.com/immune-gmbh/attestation-sdk/ $${THRIFT_FILE} ; \
	done
	go fmt ./gen-go/...

thrift-move:
	for GENERATED_PATH in $(shell find gen-go -name generated | sed -e 's%gen-go/%%g' -e 's%/generated$$%%g') ; do \
		mv gen-go/$${GENERATED_PATH}/generated $${GENERATED_PATH}/generated ; \
	done
	rm -rf ./gen-go

thrift: thrift-cleanup thrift-generate thrift-move

afascli: builddir
	go build -o build/afascli ./cmd/afascli

afasd: builddir
	go build -o build/afasd ./cmd/afasd

hwsecvalidator: builddir
	go build -o build/hwsecvalidator ./tools/hwsecvalidator

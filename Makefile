all: docs thrift afascli afasd hwsecvalidator

docs:
	for PLANTUML_FILE in doc/*.plantuml ; do \
		plantuml -png $${PLANTUML_FILE} ; \
	done

builddir:
	mkdir -p build

thrift:
	rm -rf gen-go
	find . -type l -name generated -exec rm -f {} +
	for THRIFT_FILE in if/afas.thrift if/txt_errors.thrift if/device.thrift doc/v2/if/service.thrift ; do \
		thrift -r --gen go:package_prefix=github.com/immune-gmbh/AttestationFailureAnalysisService/ $${THRIFT_FILE} ; \
	done
	go fmt ./gen-go/...
	for GENERATED_PATH in $(shell find gen-go -name generated | sed -e 's%gen-go/%%g' -e 's%/generated$$%%g') ; do \
		ln -s `realpath --relative-to=$${GENERATED_PATH} gen-go/$${GENERATED_PATH}`/generated $${GENERATED_PATH}/generated ; \
	done

afascli: builddir
	go build -o build/afascli ./cmd/afascli

afasd: builddir
	go build -o build/afasd ./cmd/afasd

hwsecvalidator: builddir
	go build -o build/hwsecvalidator ./tools/hwsecvalidator

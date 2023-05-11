all: thrift afascli afasd hwsecvalidator

builddir:
	mkdir -p build

thrift:
	thrift -r --gen go if/afas.thrift

afascli: builddir
	go build -o build/afascli ./cmd/afascli

afasd: builddir
	go build -o build/afasd ./cmd/afasd

hwsecvalidator: builddir
	go build -o build/afasd ./tools/hwsecvalidator

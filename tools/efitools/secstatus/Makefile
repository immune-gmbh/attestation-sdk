
PWD=$(shell pwd)
IMAGE_NAME="xaionaro2/edk2-builder:edk2-stable202011"

all: fmt build/secstatus.efi run

build/secstatus.efi:
	mkdir -p build
	docker run -e BUILD_TARGET=RELEASE --rm -v $(PWD)/src:/home/edk2/src -v $(PWD)/build:/home/edk2/out $(IMAGE_NAME)
	@echo
	@echo "SUCCESS"
	@echo
	@ls -ld build/RELEASE_GCC5/X64/secstatus.efi

fmt:
	astyle --style=linux --indent=tab --indent-cases --indent-switches --indent-preproc-define --break-blocks --pad-oper --pad-paren --delete-empty-lines src/*.[ch]

run:
	uefi-run -s 128 -b /home/xaionaro/firmware/OVMF.fd -q $(shell which kvm) ./build/RELEASE_GCC5/X64/secstatus.efi

clean:
	rm -rf build


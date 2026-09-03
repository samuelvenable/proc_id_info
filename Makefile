.PHONY: build

build:
	cd example && chmod u+x ./build.sh && ./build.sh

prerequisites: build

target: prerequisites

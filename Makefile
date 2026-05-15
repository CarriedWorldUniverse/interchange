VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/CarriedWorldUniverse/interchange/internal/version.Version=$(VERSION)

.PHONY: build test vet version clean

build:
	go build -ldflags '$(LDFLAGS)' -o bin/interchange ./cmd/interchange
	go build -o bin/db-inspect ./cmd/db-inspect

test:
	go test -race ./...

vet:
	go vet ./...

version:
	@echo $(VERSION)

clean:
	rm -rf bin/

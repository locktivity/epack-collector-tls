.PHONY: build build-all test lint clean sdk-test sdk-run

BINARY_NAME := epack-collector-tls
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --verify HEAD 2>/dev/null || echo "unknown")

build:
	go build -ldflags "-X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)'" -o $(BINARY_NAME) ./cmd/epack-collector-tls

build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)'" -o $(BINARY_NAME)-linux-amd64 ./cmd/epack-collector-tls
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)'" -o $(BINARY_NAME)-linux-arm64 ./cmd/epack-collector-tls
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)'" -o $(BINARY_NAME)-darwin-amd64 ./cmd/epack-collector-tls
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)'" -o $(BINARY_NAME)-darwin-arm64 ./cmd/epack-collector-tls

test:
	go test -race -v ./...

GOLANGCI_LINT_VERSION := v2.9.0
GOLANGCI_LINT := ./bin/golangci-lint

$(GOLANGCI_LINT):
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b ./bin $(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./...

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*

sdk-test: build
	epack sdk test ./$(BINARY_NAME)

sdk-run: build
	epack sdk run ./$(BINARY_NAME)

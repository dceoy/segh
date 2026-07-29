.PHONY: all build fmt lint test tools vet

all: fmt vet test lint build

build:
	go build -trimpath -ldflags="-s -w" -o bin/segh ./cmd/segh

fmt:
	@test -z "$$(gofmt -l $$(find cmd internal -name '*.go' -type f))"

vet:
	go vet ./...

test:
	go test -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run

tools:
	aqua install

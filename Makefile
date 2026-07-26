.PHONY: format check-format build test vet race verify

GO_FILES := $(shell find . -type f -name '*.go')

format:
	gofmt -w $(GO_FILES)

check-format:
	@test -z "$$(gofmt -l $(GO_FILES))" || \
		(echo "Go source requires gofmt:"; gofmt -l $(GO_FILES); exit 1)

build:
	go build ./cmd/...

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...

verify: check-format build test vet race

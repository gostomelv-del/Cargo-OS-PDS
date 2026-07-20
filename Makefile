.PHONY: format test vet race verify

format:
	gofmt -w evaluation third_party/google_uuid

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...

verify: format test vet race

# CargoCore Go — Stage 6

This directory contains the reconstructed Stage 6 Go module extracted from
`CargoCore_Go_Stage6_Full_Code_ENGLISH.txt`.

## Requirements

- Go 1.22 or later

## Verification

Run from this directory:

```sh
gofmt -w evaluation third_party/google_uuid
go test ./...
go vet ./...
go test -race ./...
```

Alternatively, run the complete Stage 7 verification sequence:

```sh
make verify
```

The included GitHub Actions workflow performs the same checks automatically on
every push and pull request.

The `github.com/google/uuid` dependency is replaced by the local
`third_party/google_uuid` module, so the build does not require downloading
that dependency.

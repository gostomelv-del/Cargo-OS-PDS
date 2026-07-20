# CargoCore Go — Stage 6

This directory contains the reconstructed Stage 6 Go module extracted from
`CargoCore_Go_Stage6_Full_Code_ENGLISH.txt`.

## Requirements

- Go 1.22 or later
- PostgreSQL 16 when durable runtime storage is enabled

## Run the HTTP API

For a local, non-durable demonstration:

```sh
go run ./cmd/pds-server
```

For durable storage, apply the migration and provide a PostgreSQL connection
URL before starting the server:

```sh
psql "$PDS_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f migrations/0001_evaluation_persistence.sql
PDS_DATABASE_URL="postgres://cargoos:cargoos@localhost:5432/cargoos?sslmode=disable" \
  go run ./cmd/pds-server
```

`PDS_HTTP_ADDRESS` optionally changes the listen address from the default
`:8080`. The process verifies the database connection at startup and shuts down
gracefully on `SIGINT` or `SIGTERM`.

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

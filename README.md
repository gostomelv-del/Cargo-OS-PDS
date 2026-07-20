# CargoCore Go — Stage 6

This directory contains the reconstructed Stage 6 Go module extracted from
`CargoCore_Go_Stage6_Full_Code_ENGLISH.txt`.

The module now includes the immutable canonical Evidence Object foundation:
source identity, session binding, canonical JSON payloads, provenance,
confidence metadata, version metadata, and SHA-256 integrity verification.
Accepted Evidence Objects can be stored idempotently in PostgreSQL; database
triggers prevent their update or deletion after acceptance.
The Evidence application service controls receipt time and schema/runtime
versions and provides the same repository contract in memory and PostgreSQL.
The domain qualification layer evaluates each object against an explicit,
versioned policy and records deterministic `QUALIFIED`, `REJECTED`, or
`UNAVAILABLE` results with machine-readable reason codes.
Complete session Evidence Sets are qualified in observation-time and Evidence-ID
order; repeated observations are rejected deterministically as duplicates or
conflicts before Rule Operators consume them.

## Requirements

- Go 1.22 or later
- PostgreSQL 16 when durable runtime storage is enabled

## Run the HTTP API

For a local, non-durable demonstration:

```sh
go run ./cmd/pds-server
```

For durable storage, provide a PostgreSQL connection URL, apply all embedded
migrations, and then start the server:

```sh
export PDS_DATABASE_URL="postgres://cargoos:cargoos@localhost:5432/cargoos?sslmode=disable"
go run ./cmd/pds-migrate
go run ./cmd/pds-server
```

The migration command serializes concurrent deployments, records the checksum
of every applied migration, and fails if an already applied migration was
modified. Existing installations can continue to apply individual SQL files
with `psql`, but managed deployments should use `pds-migrate`.

`PDS_HTTP_ADDRESS` optionally changes the listen address from the default
`:8080`. The process verifies the database connection at startup and shuts down
gracefully on `SIGINT` or `SIGTERM`.
`PDS_RUNTIME_VERSION` anchors accepted Evidence to the running build; it defaults
to `cargoos-pds.dev` for local development.

The server exposes two operational probes:

- `GET /healthz` reports process liveness.
- `GET /readyz` reports readiness. In PostgreSQL mode it verifies connectivity
  and confirms that all required PDS tables exist.

The first Evidence API endpoints are:

- `POST /v1/evidence` accepts and canonicalizes an Evidence Object.
- `GET /v1/evidence/{evidence_id}` returns the exact accepted object.
- `GET /v1/sessions/{session_id}/evidence` returns the session Evidence Set in
  deterministic observation-time and Evidence-ID order.

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

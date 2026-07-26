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
Evaluation snapshots and Decision Traces bind the exact qualified Evidence Set,
including policy version, qualification time, Evidence IDs, statuses, and reason
codes. A binding is immutable and can only be attached before Rule Outcomes are
recorded.
The rule execution application service resolves the exact bound Evidence IDs,
passes defensive copies only to required operators, and persists their outcomes
as one atomic batch. Missing, rejected, unavailable, mismatched, or corrupted
Evidence fails closed before any outcome is committed.
The first standard Rule Operator library provides deterministic `MATCH`,
inclusive `RANGE`, and absolute `TOLERANCE` evaluation over JSON Pointer values.
Numeric operators use exact decimal rational arithmetic rather than floating
point, and missing or ambiguous observations produce explicit inconclusive
outcomes.
The temporal `SEQUENCE` operator orders observations by `ObservedAt` and
Evidence ID, enforces canonical step values, and supports maximum inter-step
and total-duration windows. Missing steps are inconclusive; wrong order,
values, or timing fail explicitly.
The standard Rule Execution path also requires the exact verification
`policy_id`, immutable version, and canonical SHA-256 policy hash to be bound
before Rule Outcomes exist. The identity is persisted in snapshots, outbox
events, Decision Traces, and every Rule Operator input.
The `EXISTENCE` operator verifies that at least `min_count` qualified
observations exist for a configured Evidence type and optional source. A count
below the mandatory threshold produces an explicit failing Rule Outcome.
Policy documents declaring schema `policy.document.v1` can define all five
operators in a strict `rules` array. Unknown fields, unsupported operators,
duplicate rule IDs, and fields that do not apply to the selected operator are
rejected instead of being ignored.
The server wires this compiler through the exact immutable Policy Version
reader in both in-memory and PostgreSQL modes; Rule Execution no longer relies
on a separately registered static operator set.
The in-memory Policy Registry stores immutable canonical policy versions,
rejects overlapping effective periods, and resolves exactly one version at the
Evaluation creation time. Resolution binds the resulting policy identity and
hash only when its ordered required-rule plan exactly matches the Evaluation.
The PostgreSQL Policy Registry provides the same idempotent add and exact-time
resolution contract durably. Database constraints reject overlapping effective
periods, and triggers prevent policy versions from being updated or deleted.
Policy admission is fail-closed: registries accept only versions whose
domain-separated policy hash has been verified against a trusted, time-valid,
non-revoked signing key. The initial cryptographic profile supports `ED25519`;
admission also validates every required rule in the immutable Policy Document
before approval can create an active version.
The in-memory integration suite exercises the complete signed-policy path from
admission and exact Policy Binding through Evidence qualification, Rule
Execution, Decision Trace completion, and transactional outbox persistence.
algorithm identifiers and trust-store interfaces preserve algorithm agility,
while private signing keys remain outside the PDS.
Policy publication requires an exact Approval Record before activation. Active,
suspended, and retired states are recorded as append-only lifecycle events;
only the currently active version can be resolved for a new Evaluation, while
the immutable policy and historical lifecycle records remain available for
audit and replay.
The durable Trust Store keeps public verification keys and revocations as
immutable PostgreSQL records. Key identifiers support rotation without
overwriting historical material, and verification uses an explicit admission
time so a revoked or expired key cannot authorize a new policy admission while
previously admitted records remain reproducible.
The Policy Admission Service is the single fail-closed path into a registry: it
verifies the policy signature at an explicit time, checks the exact prior
Approval Record, activates the immutable version, and only then attempts one
registry write. Failed verification or approval cannot leave a partial policy
record.
Policy-bound Evaluation creation resolves the active immutable policy at the
creation timestamp, derives the ordered required-rule plan only from that
policy, binds its exact identity and hash, and persists the aggregate and outbox
events once. No unbound or client-defined intermediate Evaluation is stored.

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

`POST /v1/evaluations` accepts `policy_id` and an optional `session_id`. The
server resolves the active immutable policy and derives its required-rule plan;
client-supplied `required_rule_ids` are rejected.
Rule Outcomes cannot be submitted through the public HTTP API. They are written
only by the trusted Rule Execution application service after it resolves the
bound qualified Evidence Set and executes every required operator atomically.
`POST /v1/evaluations/{evaluation_id}/execute-rules` invokes that server-side
service and accepts no caller-defined rules or outcomes. Missing Evidence,
policy bindings, or registered operators fail closed without partial results.
Rule operators can be resolved through the exact bound `policy_id`, version,
SHA-256 hash, and `rule_id`. A resolver that returns an operator with a
different identity is rejected before any Evidence is evaluated or outcome is
stored.
Immutable policy versions can be retrieved by that complete identity even after
suspension or retirement. Exact lookup requires the bound SHA-256 hash and does
not expose a different document stored under the same policy ID and version.
The Policy Document Rule Resolver uses this exact lookup before invoking a rule
compiler. A failed ID, version, or hash lookup never reaches compilation, and a
compiler cannot substitute an operator with a different rule identity.

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

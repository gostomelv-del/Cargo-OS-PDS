# Cargo OS PDS — Reference MVP

Status: **v0.1.0-alpha release candidate**.

This repository is the verified Go reference MVP for the Cargo OS Policy
Decision Service. It demonstrates deterministic, policy-bound Evidence
qualification and Evaluation with immutable Decision Traces. It is not a
production deployment profile.

The implementation began as a reconstruction of the Stage 6 CargoCore source
and has since been extended into the audited reference MVP described below.

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
The same document contains a mandatory, versioned `evidence_qualification`
section that compiles trusted sources, allowed Evidence types and acquisition
methods, age and clock tolerances, confidence limits, provenance, and required
payload fields into a server-controlled Qualification Policy.
Admission rejects a required rule when any of its selectors references an
Evidence type or explicit source excluded by that same Qualification Policy;
internally contradictory policies cannot become active.
The Policy Evidence Qualification service loads that configuration only
through the Evaluation's exact bound policy identity, qualifies the complete
session Evidence Set, and atomically binds the result before Rule Execution.
Qualification commands are idempotent: once an Evidence Binding exists,
retries return that immutable binding without recalculating timestamps or
re-reading mutable session state.
Evaluation `start` and `complete` commands are also idempotent in their target
states. Network retries return the existing start timestamp or completed
Decision Trace without emitting duplicate lifecycle events.
The application service also provides a server-controlled timeout command for
CREATED and RUNNING Evaluations. It derives the applicable deadline from the
persisted lifecycle timestamp, fails closed before that deadline, and records
one immutable EXPIRED state with the stable `EVALUATION_TIMEOUT` reason.
Timeout retries return the original expiration timestamp and do not emit
duplicate outbox events.
The HTTP integration suite verifies the entire public lifecycle from Evidence
ingestion and Policy-derived Evaluation creation through qualification, Rule
Execution, completion, and retrieval of the final Decision Trace.
The server wires this compiler through the exact immutable Policy Version
reader in both in-memory and PostgreSQL modes; Rule Execution no longer relies
on a separately registered static operator set.
The initial Evidence Bundle foundation can package a finalized Decision Trace,
its exact Policy reference, and every bound Evidence Object into a
deterministically ordered manifest. Each object receives a SHA-256 digest and
the manifest receives a reproducible Bundle Root; verification detects
modification of either the manifest or any included object. A verified bundle
can be exported as a byte-deterministic `.coseb` ZIP archive containing the
canonical manifest and its exact objects. Import enforces the fixed portable
layout, size and entry limits, stored entries, canonical paths, and a complete
manifest-to-object match before integrity verification. Independent decision
verification and human-readable reports remain outside this package.
The bundle signature profile binds the canonical manifest hash and Bundle Root
to an explicit signer, key, algorithm, and signing time using domain-separated
SHA-256 and Ed25519. Verification reuses the immutable Trust Store and enforces
key validity and revocation at both signing and verification time. Signing
payloads are designed for external signers; private keys are not retained by
PDS. A successfully verified bundle can be exported with its canonical
`signature.json` envelope inside the deterministic `.coseb` layout. Signed
archive import validates the entire archive and trusted signature in one
offline operation. A trusted timestamp authority can additionally bind the
exact canonical signature, Bundle Root, serial number, and issuance time in a
canonical `timestamp.json`. Timestamped `.coseb` archives are deterministic and
can verify the bundle signer at the trusted issuance time and the timestamp
authority through a separate Trust Store. Full Policy Snapshot embedding,
attachments, reports, and independent decision recalculation remain separate
work.
The complete Evidence Bundle build path embeds the immutable canonical Policy
Version as `policy/snapshot.json` instead of a reference alone. It rehydrates
the Policy through the domain model, requires its ID, version, and calculated
hash to match the final Decision Trace binding, and places the exact snapshot
under the Bundle Root. Reference-only bundle construction remains available for
backward compatibility. Independent Rule Outcome recalculation remains
available through the fail-closed offline verifier. It rehydrates the exact
Policy and Evidence Objects from the Bundle, recompiles every required Rule
Operator with the production Policy compiler, executes the ordered rule plan,
compares status and reason codes with the stored Rule Outcomes, independently
derives the final verification result, and returns an auditable verification
report. Expired and otherwise non-completed decisions remain outside this
initial recalculation profile.
Successful independent verification can be represented as a canonical,
externally signed Verification Certificate. The certificate binds its identity,
Bundle ID and Root, Evaluation, exact Policy reference, trusted timestamp,
stored and recalculated result, and every recalculated Rule Outcome. Certificate
verification repeats the independent decision calculation and validates the
verifier key through the Trust Store; verifier private keys remain outside PDS.
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

## Release scope

The release candidate includes:

- immutable Evidence Objects and deterministic Evidence qualification;
- signed, versioned Policy admission and lifecycle controls;
- five strict Rule Operators compiled from the bound Policy Document;
- atomic Evaluation persistence, history, and transactional outbox records;
- PostgreSQL migrations, readiness checks, and operator CLIs;
- a complete HTTP integration test from Evidence ingestion to Decision Trace;
- formatting, command build, unit, vet, race, and PostgreSQL integration checks.

The public HTTP API does not yet implement authentication, authorization,
tenant isolation, rate limiting, TLS termination, or production telemetry.
Until a deployment profile supplies those controls, bind the server only to a
trusted development or integration network. See
[`docs/MVP_RELEASE_READINESS.md`](docs/MVP_RELEASE_READINESS.md) for the audited
boundary and remaining production work.

The future Cargo OS Core Runtime safety semantics are defined separately in
[`docs/CARGO_OS_FORMAL_RUNTIME_MODEL.md`](docs/CARGO_OS_FORMAL_RUNTIME_MODEL.md).
Its
[`implementation traceability matrix`](docs/CARGO_OS_FORMAL_MODEL_TRACEABILITY.md)
distinguishes current PDS coverage from missing responsibility, spatial,
sensor-fusion, physical halt-state, and Proof-of-Handover work.

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

Signed policies are admitted through a separate operator command, not through
the public HTTP API:

```sh
go run ./cmd/pds-policy-admit signed-policy.json
```

The command requires `PDS_DATABASE_URL` and accepts either one JSON file or
standard input. Its request contains the immutable Policy Snapshot (including
its canonical hash), Ed25519 Signature, exact Approval Record, and explicit
verification and activation timestamps. Input is limited to 1 MiB, unknown
fields and trailing JSON are rejected, and the existing fail-closed Policy
Admission Service performs signature, document, approval, and effective-scope
validation before the PostgreSQL registry is changed. Private signing keys
remain outside PDS.

Active policy versions can be removed from new Evaluation resolution through a
separate operator command:

```sh
go run ./cmd/pds-policy-lifecycle suspend cargo-transfer 1.0.0 2026-07-26T10:30:00Z
go run ./cmd/pds-policy-lifecycle retire cargo-transfer 1.0.0 2026-07-27T10:30:00Z
```

The command requires `PDS_DATABASE_URL` and an explicit RFC3339 event time.
`suspend` temporarily removes an active version from resolution; `retire`
permanently ends its lifecycle. Only the domain-defined transitions
`ACTIVE → SUSPENDED`, `ACTIVE → RETIRED`, and `SUSPENDED → RETIRED` are
accepted. Lifecycle records remain append-only, and exact historical Policy
Versions stay available for deterministic Evaluation replay. Retrying the exact
same transition and event time is idempotent; conflicting retries fail closed.

Public Ed25519 verification keys are administered through another bounded
operator command:

```sh
go run ./cmd/pds-trust-key register-key.json
go run ./cmd/pds-trust-key revoke-key.json
```

The command requires `PDS_DATABASE_URL` and accepts one strict JSON object from
a file or standard input. A `register` request contains `signer_id`, `key_id`,
`algorithm`, a base64 `public_key`, `valid_from`, and optional `valid_until`. A
`revoke` request contains only the key identity and `revoked_at`. Input is
limited to 1 MiB; unknown, mixed-action, unsupported-algorithm, malformed-key,
and trailing fields fail closed. Registration and revocation are append-only
and idempotent for exact retries. Private keys never enter PDS.

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
`POST /v1/evaluations/{evaluation_id}/qualify-evidence` accepts no
caller-defined qualification settings. It derives them from the exact Policy
Version already bound to the Evaluation and atomically binds the qualified
Evidence Set.
Rule Outcomes cannot be submitted through the public HTTP API. They are written
only by the trusted Rule Execution application service after it resolves the
bound qualified Evidence Set and executes every required operator atomically.
Every command endpoint accepts exactly one JSON value with a hard 1 MiB request
limit. Unknown fields and trailing JSON values are rejected before an
application service is invoked; oversized bodies return
`413 request_body_too_large`.
HTTP errors use stable public codes. Unknown storage or runtime failures return
`500 internal_error`; internal error text is never copied into a response.
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
make check-format
go build ./cmd/...
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

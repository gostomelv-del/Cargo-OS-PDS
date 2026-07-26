# Cargo OS PDS Reference MVP Release Readiness

## Baseline

- Candidate version: `v0.1.0-alpha`
- Audited branch: `main`
- Runtime: Go 1.22 or later
- Durable profile: PostgreSQL 16
- Classification: reference MVP; not production-ready

This baseline covers the Policy Decision Service only. It does not claim to
implement the complete Cargo OS responsibility-transfer platform, physical
robot control, Proof of Handover, Chain of Responsibility, or certification
framework.

## Verified capabilities

| Area | Release evidence |
| --- | --- |
| Evaluation | Immutable aggregate snapshots, guarded state transitions, idempotent start/complete, Decision Trace |
| Evidence | Canonical immutable objects, integrity checks, PostgreSQL storage, deterministic set qualification |
| Policy | Canonical hash, Ed25519 verification, approval, immutable versions, effective periods, suspend/retire |
| Rules | Strict MATCH, RANGE, TOLERANCE, EXISTENCE, and SEQUENCE compilation and execution |
| Binding | Exact Policy ID/version/hash and qualified Evidence IDs persisted through Evaluation and replay |
| Persistence | Atomic Evaluation/history/outbox writes, optimistic concurrency, append-only Policy and Trust records |
| Runtime | Versioned HTTP endpoints, strict bounded JSON, stable public errors, liveness/readiness probes |
| Operations | Managed migrations and separate Trust Key, Policy admission, and Policy lifecycle CLIs |
| Verification | Formatting, all command builds, unit tests, vet, race detector, PostgreSQL integration |

## Release verification

Run:

```sh
make verify
```

The command is non-mutating and fails if any Go source requires formatting. It
builds every command and runs unit, static-analysis, and race checks. GitHub
Actions additionally runs the PostgreSQL 16 schema and repository integration
suite.

Release approval requires a green workflow for the exact candidate commit.

## Security boundary

The PDS validates Evidence and signed Policies but does not authenticate HTTP
clients. The current HTTP listener must be placed behind deployment-provided
TLS, authentication, authorization, tenant isolation, request throttling, and
network policy. Operator CLIs rely on PostgreSQL access control and must run
only in an administrative environment.

Private signing keys are outside PDS. The Trust Store contains public
verification keys and append-only revocations only.

## Explicitly deferred

The following are outside this reference MVP and block a production-readiness
claim:

- HTTP authentication and authorization;
- tenant identity and data isolation;
- TLS and secret-management integration;
- metrics, tracing, structured operational audit export, and alerting;
- backup, restore, disaster recovery, and high-availability procedures;
- rate limiting, abuse protection, and capacity validation;
- container/orchestrator manifests and production deployment profiles;
- external broker delivery for transactional outbox records;
- conformance, interoperability, penetration, and performance certification;
- public license selection and a signed/tagged release.

These items must be implemented and independently verified by the applicable
deployment or certification profile. Their absence does not weaken the
deterministic PDS domain invariants, but it prevents production exposure of the
current HTTP process.

## Release decision

The repository is suitable for:

- architecture validation;
- deterministic PDS integration;
- controlled demonstrations;
- PostgreSQL-backed development and testing;
- extension toward an authenticated deployment profile.

It is not suitable for direct public-network or multi-tenant production use.

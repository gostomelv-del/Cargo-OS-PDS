# Changelog

All notable changes to the Cargo OS PDS reference implementation are recorded
here.

## [Unreleased]

### Added

- Release-readiness audit and explicit reference-MVP security boundary.
- Non-mutating formatting verification and build checks for every command.
- Server-controlled CREATED and RUNNING Evaluation timeout policy with
  idempotent expiration, a stable `EVALUATION_TIMEOUT` reason, Decision Trace
  coverage, and restart recovery tests.
- PostgreSQL failure-recovery coverage proving that an outbox write failure
  rolls back the aggregate snapshot and that an exact retry persists one
  consistent state and event.

## [0.1.0-alpha] - 2026-07-26

### Added

- Deterministic Evaluation aggregate, snapshots, Decision Trace, history, and
  transactional outbox.
- Immutable Evidence Objects, qualification, PostgreSQL storage, and HTTP
  ingestion.
- Signed immutable Policies, durable Trust Store, lifecycle state, admission,
  exact resolution, and operator CLIs.
- Strict MATCH, RANGE, TOLERANCE, EXISTENCE, and SEQUENCE Rule Operators.
- Policy-bound Evidence qualification and server-side Rule Execution.
- Versioned HTTP lifecycle with bounded strict JSON and stable public errors.
- Managed PostgreSQL migrations, health/readiness probes, and CI verification.

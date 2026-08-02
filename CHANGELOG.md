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
- Initial Evidence Bundle foundation with a deterministic manifest, exact
  Policy and Evidence references, per-object SHA-256 digests, a Bundle Root,
  and modification detection.
- Deterministic `.coseb` ZIP export and offline import with a fixed portable
  layout, bounded entries and size, path-traversal protection, and mandatory
  manifest/object integrity verification.
- Domain-separated Ed25519 Evidence Bundle signatures binding the canonical
  manifest hash and Bundle Root to an explicit signer, trusted key, algorithm,
  and signing time with key validity and revocation enforcement.
- Trusted timestamp authority envelopes binding the exact bundle signature,
  Bundle Root, serial number, and issuance time, with deterministic
  `timestamp.json` embedding and offline timestamped archive verification.
- Canonical `signature.json` embedding in deterministic `.coseb` archives and
  one-step offline archive, integrity, Trust Store, and signature verification.

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

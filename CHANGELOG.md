# Changelog

All notable changes to the Cargo OS PDS reference implementation are recorded
here.

## [Unreleased]

### Added

- Allocation-free 3D spatial estimate contracts with declared coordinate
  frame, floor, confidence, versioned estimator/calibration metadata, compact
  covariance, finite-number checks, and positive-semidefinite validation.
- Deterministic Responsibility safety state machine with fail-safe HALT,
  retained responsibility, fresh versioned-Evidence recovery, and stale
  authorization rejection.
- Allocation-free pending handover storage on the transfer/commit hot path;
  defensive slices are created only for explicit collection access.
- Concurrent Responsibility handover delivery with bounded claims, worker
  leases, `SKIP LOCKED`, publication ownership, and expired-lock recovery.
- Atomic Responsibility handover commits that update the sole assignment and
  append an immutable delivery event in one memory or PostgreSQL operation.
- Versioned memory and PostgreSQL Responsibility repositories with optimistic
  concurrency control that permits only one winning assignment per Object.
- Typed Physical Object and Participant identities with an invariant-preserving
  Responsibility aggregate, deterministic transfer, snapshots, domain events,
  and defensive state boundaries.
- Normative Cargo OS Core Runtime mathematical model and implementation
  traceability matrix separating the current PDS boundary from future
  responsibility, spatial, probabilistic sensor-fusion, fail-safe halt, and
  Proof-of-Handover capabilities.
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
- Complete immutable Policy Snapshot embedding with canonical document,
  required-rule plan, effective period, hash rehydration, Decision Trace
  binding, and portable archive round-trip verification.
- Fail-closed independent offline decision verification using the embedded
  Policy Snapshot, exact Evidence Objects, production Rule Operator compiler,
  recalculated Rule Outcomes, and independently derived final result.
- Canonical externally signed Verification Certificates binding the Bundle
  Root, trusted timestamp, Policy, stored and recalculated results, and exact
  independently reproduced Rule Outcomes.

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

# Cargo OS Formal Model Traceability

Status: controlling implementation delta  
Audited repository: `gostomelv-del/Cargo-OS-PDS`  
Audited baseline: this change, based on `main` at
`4873e7c47cbd9f5ddef65ba3780a016c8b94a560`

## 1. Status definitions

- `Implemented`: executable behavior and tests exist.
- `Partial`: a narrower prerequisite exists.
- `Missing`: no executable implementation exists here.
- `Research-dependent`: calibrated hardware/environment validation is needed.
- `Out of PDS scope`: belongs to Cargo OS Core Runtime or hardware integration.

## 2. Requirement matrix

| ID | Requirement | Status | Current evidence / closure |
|---|---|---|---|
| FM-01 | Exactly one responsible Participant per Object | Implemented | Invariant-preserving aggregate plus versioned memory and PostgreSQL repositories reject competing assignments for the same Object |
| FM-02 | Atomic responsibility handover | Implemented for responsibility state | Service and memory/PostgreSQL Unit of Work commit the sole assignment with its immutable handover event; physical actuation remains Core Runtime scope |
| FM-03 | Immutable canonical observation | Implemented | `evidence/object.go`, canonical JSON, integrity, defensive snapshots |
| FM-04 | Confidence in `[0,1]` | Implemented | Evidence validation and tests |
| FM-05 | Policy minimum confidence | Implemented | Qualification and Policy compiler |
| FM-06 | Evidence TTL | Implemented | `MaxAge` and stale reason code |
| FM-07 | Future timestamp tolerance | Implemented | `FutureTolerance` qualification |
| FM-08 | Provenance/acquisition constraints | Implemented | Source, type, method, provenance, payload checks |
| FM-09 | Position in declared 3D frame | Missing | Add spatial estimate and frame registry |
| FM-10 | Proximity `d <= d_max` | Missing | Add spatial operator, units, frame and boundary tests |
| FM-11 | Discrete floor consistency | Missing | Add floor hypotheses and transition operator |
| FM-12 | Covariance/bounded uncertainty | Missing | Scalar confidence alone is insufficient |
| FM-13 | Bayesian estimator interface | Missing / Out of PDS scope | Define versioned estimator port and output snapshot |
| FM-14 | Gaussian filter profile | Research-dependent | Calibrate models and matrices; validate datasets |
| FM-15 | Particle filter profile | Research-dependent | Define likelihood, ESS, resampling, replay, benchmarks |
| FM-16 | Wi-Fi/BLE profile | Research-dependent | Add device/environment calibration and acceptance tests |
| FM-17 | Barometric profile | Research-dependent | Add compensation, floor map, multimodal corroboration |
| FM-18 | Deterministic Policy execution | Implemented | Production Rule Operators and ordered rule plan |
| FM-19 | Invalid Evidence fails closed | Implemented for PDS | Rejected/unavailable Evidence blocks execution/completion |
| FM-20 | Mandatory physical `S_halt` | Missing / Out of PDS scope | Add runtime safety state machine and command interlock |
| FM-21 | Responsibility retained in halt | Missing | Requires FM-01 and FM-20 |
| FM-22 | Versioned halt recovery | Missing | Add fresh-Evidence recovery transitions |
| FM-23 | Atomic state/outbox persistence | Implemented for Evaluation | Reuse Unit of Work pattern for handover |
| FM-24 | Immutable Decision Trace | Implemented | Snapshot recovery and Evidence Bundle |
| FM-25 | Exact Policy/Evidence binding | Implemented | Policy Snapshot, objects, Bundle Root |
| FM-26 | Independent decision recalculation | Implemented | Offline production-rule replay |
| FM-27 | Signature and trusted timestamp | Implemented in Cargo OS profile | RFC 3161 remains separate |
| FM-28 | Signed Verification Certificate | Implemented | Canonical machine-readable certificate |
| FM-29 | Proof of Handover | Missing / Out of PDS scope | Bind physical before/after responsibility and transaction root |
| FM-30 | Unified append-only hash chain | Partial | Immutable records and roots exist; `previousRoot` ledger does not |
| FM-31 | Deterministic estimator replay | Partial | Decision replay exists; estimator metadata does not |
| FM-32 | Matrix/NaN/infinity validation | Missing for estimator layer | Add numerical-safety package and tests |

## 3. Existing executable foundation

The current PDS already provides canonical Evidence, versioned qualification,
immutable Policies, deterministic Rule Operators, atomic outcomes, guarded
Evaluation transitions, PostgreSQL Unit of Work and outbox, Decision Trace,
complete Policy Snapshot, portable signed/timestamped Evidence Bundle,
independent decision replay, and signed Verification Certificates.

These capabilities MUST NOT be described as implementation of probabilistic
sensor fusion, physical responsibility transfer, or Proof of Handover.

## 4. Implementation sequence

### Phase A — contracts

Add Participant, Object, Responsibility, spatial estimate, frame, covariance,
floor hypothesis, estimator profile, and new admissibility reason codes.

Exit: canonical snapshots reject invalid numerical and identity states.

### Phase B — deterministic spatial admissibility

Add frame compatibility, proximity, floor consistency, Policy compiler support,
and independent replay.

Exit: identical Policy and Evidence yield identical decisions and reasons.

### Phase C — runtime safety

Add Responsibility conservation, proposed/verified/committed/rejected/HALT
states, motion interlock, fresh-Evidence recovery, and crash/concurrency tests.

Exit: no reachable committed state has zero or multiple responsible parties.

### Phase D — estimator plug-in boundary

Add versioned estimator input/output, calibration metadata, uncertainty and
confidence contract, and immutable estimator output recording.

Exit: PDS and transition logic remain independent of filter implementation.

### Phase E — calibrated profiles

Validate Gaussian, particle, radio, inertial, barometric, and optical profiles
individually against datasets, hardware metadata, failure budgets, benchmarks,
and acceptance thresholds.

Exit: empirical results support declared confidence/error bounds.

### Phase F — handover proof

Add atomic responsibility update plus audit append, hash-linked transactions,
Bundle binding to before/after responsibility, signer roles, and independent
handover verification.

Exit: a portable proof establishes Object, Participants, responsibility change,
Evidence, Policy, decision, time, and transaction lineage.

## 5. Documentation controls

- No `Implemented` status without executable tests.
- No `Validated` probabilistic profile without calibrated empirical results.
- No named research attribution without a precise bibliography.
- No deployment-specific filter inside PDS domain packages.
- Update this baseline and matrix after each closing PR.

# Cargo OS Formal Model Traceability

Status: controlling implementation delta  
Audited repository: `gostomelv-del/Cargo-OS-PDS`  
Audited baseline: this change, based on `main` at
`38e07b541f3d144ea4338d5ef48a0bc9f992aaaa`

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
| FM-09 | Position in declared 3D frame | Implemented contract | `spatial.Estimate` requires a declared frame, finite 3D position, floor, time, and versioned metadata; frame transforms remain future work |
| FM-10 | Proximity `d <= d_max` | Implemented contract | Frame-compatible overflow-safe Euclidean proximity with exact boundary tests and deterministic failure mask |
| FM-11 | Discrete floor consistency | Implemented contract | Same-floor interaction plus version-continuous, Policy-calibrated `Δfloor`/`ΔZ`, confidence, timing, and bounded-step transition operator; hardware calibration remains profile validation |
| FM-12 | Covariance/bounded uncertainty | Implemented contract | Compact symmetric 3x3 covariance with finite and positive-semidefinite validation |
| FM-13 | Bayesian estimator interface | Implemented contract | Algorithm-neutral single-observation recursive port binds prior Estimate, immutable Observation digest, target frame, and exact profile/calibration versions |
| FM-14 | Gaussian filter profile | Research-dependent | Calibrate models and matrices; validate datasets |
| FM-15 | Particle filter profile | Research-dependent | Define likelihood, ESS, resampling, replay, benchmarks |
| FM-16 | Wi-Fi/BLE profile | Research-dependent | Add device/environment calibration and acceptance tests |
| FM-17 | Barometric profile | Research-dependent | Add compensation, floor map, multimodal corroboration |
| FM-18 | Deterministic Policy execution | Implemented | Production Rule Operators and ordered rule plan |
| FM-19 | Invalid Evidence fails closed | Implemented for PDS | Rejected/unavailable Evidence blocks execution/completion |
| FM-20 | Mandatory physical `S_halt` | Partial / Out of PDS scope | Deterministic software HALT blocks commits and motion authorization; physical command interlock remains deployment work |
| FM-21 | Responsibility retained in halt | Implemented for state machine | HALT preserves the last committed Responsibility snapshot and rejects commits |
| FM-22 | Versioned halt recovery | Implemented for state machine | Recovery requires fresh admissible Evidence with explicit Policy/Evidence versions and exact responsibility binding |
| FM-23 | Atomic state/outbox persistence | Implemented | Evaluation and Responsibility Unit of Work plus concurrent lease-based delivery |
| FM-24 | Immutable Decision Trace | Implemented | Snapshot recovery and Evidence Bundle |
| FM-25 | Exact Policy/Evidence binding | Implemented | Policy Snapshot, objects, Bundle Root |
| FM-26 | Independent decision recalculation | Implemented | Offline production-rule replay |
| FM-27 | Signature and trusted timestamp | Implemented in Cargo OS profile | RFC 3161 remains separate |
| FM-28 | Signed Verification Certificate | Implemented | Canonical machine-readable certificate |
| FM-29 | Proof of Handover | Partial / Out of PDS scope | Atomic handover root now binds Object, before/after Participants, version, and time; physical Evidence, Policy/decision, signer proof, and portable verification remain |
| FM-30 | Unified append-only hash chain | Partial | Ledger rejects forks; estimator results and responsibility handovers commit atomically with verified typed roots; Evaluation and Bundle attachment remain |
| FM-31 | Deterministic estimator replay | Partial | Exact replay metadata and immutable PostgreSQL result recording exist; deterministic execution of calibrated profiles remains research-dependent |
| FM-32 | Matrix/NaN/infinity validation | Implemented for spatial contract | Position, confidence, and covariance reject NaN/infinity; normalized PSD checks avoid determinant overflow |

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

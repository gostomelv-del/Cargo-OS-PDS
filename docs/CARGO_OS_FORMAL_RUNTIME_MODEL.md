# Cargo OS Formal Runtime Model

Status: normative architecture model; partially implemented  
Version: 1.0.0-draft  
Date: 2026-08-02

## 1. Scope and conformance boundary

This document defines the formal safety and Evidence semantics for the future
Cargo OS Core Runtime: responsibility conservation, spatial and temporal
validity, probabilistic estimation, deterministic fail-safe transitions,
atomic handover, and audit traceability.

The Cargo OS PDS reference MVP implements only the subset identified in
`CARGO_OS_FORMAL_MODEL_TRACEABILITY.md`. This document does not claim that the
repository already implements physical responsibility transfer, sensor fusion,
Proof of Handover, or robot motion control.

A conforming implementation MUST declare its supported runtime, sensor,
estimator, spatial, and handover profiles.

## 2. Sets, spaces, and identifiers

Let:

- \(\mathcal P\): valid Participants;
- \(\mathcal O\): managed Physical Objects;
- \(\mathcal E\): immutable raw observations;
- \(\mathcal A\): Admissible Evidence tokens;
- \(\mathcal S\): protocol states, including mandatory \(S_{halt}\);
- \(\mathcal T=\mathbb R_{\ge0}\): monotonic runtime time;
- \(\mathcal X\subseteq\mathbb R^n\): estimator state space;
- \(\mathcal Q=\mathbb R^3\times\mathbb Z\): position plus floor;
- \(\mathcal L\): append-only audit log.

Identifiers for Participants, Objects, Evidence, Policies, transfers, and
transactions MUST be non-empty and unambiguous in their declared namespace.

## 3. Responsibility conservation

Define

\[
R:\mathcal O\times\mathcal T\rightarrow\mathcal P.
\]

Exactly one Participant MUST be responsible for each Object at every committed
runtime instant:

\[
\forall o\in\mathcal O,\forall t\in\mathcal T:\quad
\exists!p\in\mathcal P:R(o,t)=p,
\]

equivalently,

\[
\sum_{p\in\mathcal P}\mathbf1[R(o,t)=p]=1.
\]

A handover MUST be atomic. A committed state with zero or multiple responsible
Participants is invalid.

## 4. Observation and Evidence model

An immutable observation is

\[
e=(id_e,source,type,z,t_{obs},t_{recv},frame,provenance,integrity).
\]

A probabilistic Evidence token is

\[
a=(id_a,\hat x_t,\Sigma_t,c_t,t_a,q_o,q_p,profile,provenance),
\]

where \(\hat x_t\) is estimated state, \(\Sigma_t\) is covariance or equivalent
uncertainty, \(c_t\in[0,1]\) is confidence, and
\(q=(x,y,z,f)\in\mathcal Q\). The estimator and calibration profiles MUST be
versioned. Point estimates require bounded uncertainty metadata.

## 5. Admissibility predicate

For policy parameters \(\theta_{min}\), \(\Delta t_{max}\), clock tolerance
\(\epsilon_f\), and \(d_{max}\), define

\[
Valid(a,t)=C(a)\land T(a,t)\land D(a)\land F(a)\land I(a).
\]

### 5.1 Confidence

\[
C(a)\iff c_t\ge\theta_{min}.
\]

One permitted covariance profile is

\[
c_t=\exp(-\lambda\operatorname{tr}(W\Sigma_t)),\quad\lambda>0,
\]

with declared positive semidefinite normalization matrix \(W\). This is a
replaceable profile, not a universal algorithm.

### 5.2 Time

\[
T(a,t)\iff 0\le t-t_a\le\Delta t_{max}.
\]

Bounded clock uncertainty MAY allow \(t_a-t\le\epsilon_f\). Safety ordering
MUST use a monotonic source.

### 5.3 Space

For compatible coordinate frames and positive semidefinite metric \(M\):

\[
d_M(q_o,q_p)=\sqrt{(r_o-r_p)^TM(r_o-r_p)},
\qquad D(a)\iff d_M(q_o,q_p)\le d_{max}.
\]

Unknown or incompatible frames MUST fail closed.

### 5.4 Floor consistency

\[
F(a)\iff(f_o=f_p)\land FloorTransitionConsistent(a).
\]

A barometric profile MAY use

\[
\Delta h\approx\frac{RT}{gM_a}\ln\left(\frac{P_0}{P}\right),
\]

but MUST declare calibration, environmental bounds, and the probabilistic
mapping from altitude to floor. Pressure alone MUST NOT authorize a floor
transition below the policy confidence threshold.

### 5.5 Integrity and provenance

\[
I(a)\iff Hash(payload)=digest_a\land Trusted(provenance_a).
\]

Sources, acquisition methods, schemas, runtime versions, and required
provenance MUST be policy-bound.

## 6. Probabilistic estimator profiles

Cargo OS consumes estimator output through a versioned interface and MUST NOT
require one universal filter.

### 6.1 Bayesian recursion

\[
p(x_t\mid z_{1:t})=\eta p(z_t\mid x_t)
\int p(x_t\mid x_{t-1},u_t)p(x_{t-1}\mid z_{1:t-1})dx_{t-1}.
\]

### 6.2 Gaussian recursive profile

\[
\hat x_t^-=f(\hat x_{t-1},u_t),\qquad
P_t^-=F_tP_{t-1}F_t^T+Q_t,
\]

\[
K_t=P_t^-H_t^T(H_tP_t^-H_t^T+R_t)^{-1},
\]

\[
\hat x_t=\hat x_t^-+K_t(z_t-h(\hat x_t^-)),\qquad
P_t=(I-K_tH_t)P_t^-.
\]

The profile MUST declare models, matrices, units, frames, calibration, and
numerical validity bounds.

### 6.3 Particle profile

\[
\{(x_t^{(m)},w_t^{(m)})\}_{m=1}^M,\qquad\sum_mw_t^{(m)}=1,
\]

\[
x_t^{(m)}\sim p(x_t\mid x_{t-1}^{(m)},u_t),
\]

\[
\tilde w_t^{(m)}=w_{t-1}^{(m)}p(z_t\mid x_t^{(m)}),\qquad
w_t^{(m)}=\frac{\tilde w_t^{(m)}}{\sum_j\tilde w_t^{(j)}}.
\]

Particle depletion is measured by

\[
N_{eff}=\frac1{\sum_m(w_t^{(m)})^2}.
\]

The profile MUST define particle budget, resampling threshold, degeneracy
handling, and replay controls. Failed normalization or unrecoverable depletion
makes Evidence inadmissible.

### 6.4 Similarity-based radio profile

For feature vector \(z\), fingerprint \(\mu_i\), and bandwidth \(\Lambda\):

\[
L_i(z)=\exp\left[-\tfrac12(z-\mu_i)^T\Lambda^{-1}(z-\mu_i)\right].
\]

Wi-Fi RSSI/FTM and BLE profiles MUST identify device, firmware, antenna,
sampling, map, environment, and calibration versions. No model is considered
calibrated without target-hardware validation.

## 7. Deterministic transition and halt

\[
\Delta:\mathcal S\times\mathcal A^*\times\mathcal P^2\times\mathcal T
\rightarrow\mathcal S.
\]

Identical canonical state, ordered Evidence, Participants, Policy, and time
input MUST produce identical output and reason codes.

\[
\neg Valid(a,t)\lor Conflict(a)\lor EstimatorFailure
\Rightarrow\Delta(s,a,p_i,p_j,t)=S_{halt}.
\]

In \(S_{halt}\), motion-enabling commands and handover commits MUST be rejected,
responsibility MUST remain with the last committed Participant, and recovery
MUST require a versioned Policy plus fresh admissible Evidence. Probabilistic
estimation MUST NOT make protocol transitions probabilistic.

## 8. Atomic handover

Let

\[
H=(id_H,o,p_i,p_j,A_H,t_H,policy).
\]

\[
Commit(H)\iff R(o,t_H^-)=p_i\land p_i\ne p_j\land
\bigwedge_{a\in A_H}Valid(a,t_H)\land PolicyAllows(H).
\]

The responsibility update and audit append occur together:

\[
(R(o,t_H^+):=p_j)\land Append(\mathcal L,\tau_H),
\]

or neither occurs.

## 9. Proof of Handover and audit

\[
\tau_H=(id_H,o,p_i,p_j,t_H,root(A_H),policyHash,decisionRoot,
previousRoot,\Pi_{HoP}).
\]

For a hash-linked log:

\[
root_i=H(canonical(\tau_i)\parallel root_{i-1}).
\]

Proof of Handover MUST bind before/after responsibility, Object, Participants,
Evidence, Policy, Decision Trace, time, and signer identities. Corrections are
new linked records. Evidence Bundle signatures, timestamps, and certificates
provide components of a proof but do not alone prove physical handover.

## 10. Numerical and conformance controls

- Units, coordinate frames, covariance conventions, and time sources MUST be
  explicit.
- NaN, infinity, invalid dimensions, and non-PSD covariance MUST be rejected.
- Threshold boundary inclusion MUST be explicit.
- Randomized estimators MUST record algorithm, parameter, calibration, and seed
  policy sufficient for audit replay.
- Safety limits MUST be versioned Policy data.
- Sensor fusion MUST be a hardware-independent plug-in boundary.
- Invalid, absent, stale, contradictory, or uncalibrated Evidence fails closed.

A conformance declaration lists sensors, estimator, calibration, frames, time
source, confidence function, limits, state machine, halt recovery, Proof of
Handover, and deterministic test evidence.

## 11. Attribution boundary

Bayesian recursion, Gaussian filtering, sequential Monte Carlo, radio
fingerprinting, and barometric altitude estimation are general frameworks.
This specification does not attribute a formula to a named researcher without
a precise bibliographic source. Project use of publications MUST record exact
references, assumptions, licenses, and engineering deviations separately.

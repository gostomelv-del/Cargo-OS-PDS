package evaluation

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var ErrSnapshotVersionRequired = errors.New("evaluation: snapshot version required")

// EvaluationSnapshot is the stable persistence boundary for an aggregate.
// Domain events are intentionally excluded because they are persisted through
// the transactional outbox.
type EvaluationSnapshot struct {
	EvaluationID       uuid.UUID
	SessionID          uuid.UUID
	State              EvaluationState
	Result             VerificationResult
	ReasonCodes        []ReasonCode
	CreatedAt          time.Time
	StartedAt          *time.Time
	CompletedAt        *time.Time
	CancelledAt        *time.Time
	ExpiredAt          *time.Time
	CancellationReason string
	Version            uint64
	RequiredRuleIDs    []string
	RuleOutcomes       []RuleOutcome
	Checkpoints        []EvaluationCheckpoint
	History            []EvaluationHistoryEntry
	EvidenceBinding    *EvidenceSetBinding
	PolicyBinding      *PolicyBinding
}

func (e *EvaluationAggregate) Snapshot() (EvaluationSnapshot, error) {
	if e == nil {
		return EvaluationSnapshot{}, ErrInvalidEvaluationSnapshot
	}
	return EvaluationSnapshot{
		EvaluationID:       e.id,
		SessionID:          e.sessionID,
		State:              e.state,
		Result:             e.result,
		ReasonCodes:        copyReasonCodes(e.reasonCodes),
		CreatedAt:          e.createdAt,
		StartedAt:          copyTimePointer(e.startedAt),
		CompletedAt:        copyTimePointer(e.completedAt),
		CancelledAt:        copyTimePointer(e.cancelledAt),
		ExpiredAt:          copyTimePointer(e.expiredAt),
		CancellationReason: e.cancellationReason,
		Version:            e.version,
		RequiredRuleIDs:    append([]string(nil), e.requiredRuleIDs...),
		RuleOutcomes:       copyRuleOutcomes(e.ruleOutcomes),
		Checkpoints:        e.Checkpoints(),
		History:            copyEvaluationHistory(e.history),
		EvidenceBinding:    copyEvidenceBinding(e.evidenceBinding),
		PolicyBinding:      copyPolicyBinding(e.policyBinding),
	}, nil
}

func RehydrateEvaluation(snapshot EvaluationSnapshot) (*EvaluationAggregate, error) {
	if err := validateEvaluationSnapshot(snapshot); err != nil {
		return nil, err
	}
	checkpoints := make(map[string]EvaluationCheckpoint, len(snapshot.Checkpoints))
	for _, checkpoint := range snapshot.Checkpoints {
		if checkpoint.Name == "" || checkpoint.CreatedAt.IsZero() {
			return nil, ErrInvalidEvaluationSnapshot
		}
		if _, exists := checkpoints[checkpoint.Name]; exists {
			return nil, ErrInvalidEvaluationSnapshot
		}
		checkpoint.RuleOutcomes = copyRuleOutcomes(checkpoint.RuleOutcomes)
		checkpoints[checkpoint.Name] = checkpoint
	}
	if len(checkpoints) == 0 {
		checkpoints = nil
	}
	return &EvaluationAggregate{
		id:                 snapshot.EvaluationID,
		sessionID:          snapshot.SessionID,
		state:              snapshot.State,
		result:             snapshot.Result,
		reasonCodes:        copyReasonCodes(snapshot.ReasonCodes),
		createdAt:          snapshot.CreatedAt.UTC(),
		startedAt:          copyTimePointer(snapshot.StartedAt),
		completedAt:        copyTimePointer(snapshot.CompletedAt),
		cancelledAt:        copyTimePointer(snapshot.CancelledAt),
		expiredAt:          copyTimePointer(snapshot.ExpiredAt),
		cancellationReason: snapshot.CancellationReason,
		version:            snapshot.Version,
		ruleOutcomes:       copyRuleOutcomes(snapshot.RuleOutcomes),
		requiredRuleIDs:    append([]string(nil), snapshot.RequiredRuleIDs...),
		checkpoints:        checkpoints,
		history:            copyEvaluationHistory(snapshot.History),
		evidenceBinding:    copyEvidenceBinding(snapshot.EvidenceBinding),
		policyBinding:      copyPolicyBinding(snapshot.PolicyBinding),
	}, nil
}

func validateEvaluationSnapshot(snapshot EvaluationSnapshot) error {
	if snapshot.EvaluationID == uuid.Nil || snapshot.SessionID == uuid.Nil {
		return ErrInvalidEvaluationSnapshot
	}
	if snapshot.Version == 0 {
		return ErrSnapshotVersionRequired
	}
	if snapshot.CreatedAt.IsZero() || !snapshot.Result.IsValid() {
		return ErrInvalidEvaluationSnapshot
	}
	switch snapshot.State {
	case StateCreated:
		if snapshot.StartedAt != nil || snapshot.CompletedAt != nil || snapshot.CancelledAt != nil || snapshot.ExpiredAt != nil {
			return ErrInvalidEvaluationSnapshot
		}
	case StateRunning:
		if snapshot.StartedAt == nil || snapshot.CompletedAt != nil || snapshot.CancelledAt != nil || snapshot.ExpiredAt != nil {
			return ErrInvalidEvaluationSnapshot
		}
	case StateCompleted:
		if snapshot.StartedAt == nil || snapshot.CompletedAt == nil || snapshot.Result == ResultUnknown {
			return ErrInvalidEvaluationSnapshot
		}
	case StateCancelled:
		if snapshot.CancelledAt == nil || snapshot.CancellationReason == "" {
			return ErrInvalidEvaluationSnapshot
		}
	case StateExpired:
		if snapshot.ExpiredAt == nil {
			return ErrInvalidEvaluationSnapshot
		}
	default:
		return ErrInvalidEvaluationSnapshot
	}
	for _, outcome := range snapshot.RuleOutcomes {
		if _, err := normalizeRuleOutcome(outcome); err != nil {
			return ErrInvalidEvaluationSnapshot
		}
	}
	for _, entry := range snapshot.History {
		if err := validateEvaluationHistoryEntry(entry); err != nil {
			return ErrInvalidEvaluationSnapshot
		}
	}
	if snapshot.EvidenceBinding != nil {
		binding, err := normalizeEvidenceBinding(*snapshot.EvidenceBinding)
		if err != nil || binding.SessionID != snapshot.SessionID {
			return ErrInvalidEvaluationSnapshot
		}
	}
	if snapshot.PolicyBinding != nil {
		binding, err := normalizePolicyBinding(*snapshot.PolicyBinding)
		if err != nil || binding.BoundAt.Before(snapshot.CreatedAt) {
			return ErrInvalidEvaluationSnapshot
		}
	}
	return nil
}

type DecisionTrace struct {
	EvaluationID    uuid.UUID
	SessionID       uuid.UUID
	Version         uint64
	State           EvaluationState
	Result          VerificationResult
	ReasonCodes     []ReasonCode
	RequiredRuleIDs []string
	MissingRuleIDs  []string
	RuleOutcomes    []RuleOutcome
	CreatedAt       time.Time
	StartedAt       *time.Time
	CompletedAt     *time.Time
	EvidenceBinding *EvidenceSetBinding
	PolicyBinding   *PolicyBinding
}

func (e *EvaluationAggregate) DecisionTrace() (DecisionTrace, error) {
	if e == nil {
		return DecisionTrace{}, ErrInvalidEvaluationSnapshot
	}
	return DecisionTrace{
		EvaluationID:    e.id,
		SessionID:       e.sessionID,
		Version:         e.version,
		State:           e.state,
		Result:          e.result,
		ReasonCodes:     copyReasonCodes(e.reasonCodes),
		RequiredRuleIDs: append([]string(nil), e.requiredRuleIDs...),
		MissingRuleIDs:  e.MissingRequiredRuleIDs(),
		RuleOutcomes:    copyRuleOutcomes(e.ruleOutcomes),
		CreatedAt:       e.createdAt,
		StartedAt:       copyTimePointer(e.startedAt),
		CompletedAt:     copyTimePointer(e.completedAt),
		EvidenceBinding: copyEvidenceBinding(e.evidenceBinding),
		PolicyBinding:   copyPolicyBinding(e.policyBinding),
	}, nil
}

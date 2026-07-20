package pds

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
)

var (
	ErrEvaluationServiceRequired = errors.New("pds: evaluation service is required")
	ErrEvidenceReaderRequired    = errors.New("pds: evidence reader is required")
	ErrRuleOperatorRequired      = errors.New("pds: rule operator is required")
	ErrDuplicateRuleOperator     = errors.New("pds: duplicate rule operator")
	ErrRuleOperatorMissing       = errors.New("pds: required rule operator is missing")
	ErrEvidenceBindingMissing    = errors.New("pds: evaluation evidence binding is missing")
	ErrPolicyBindingMissing      = errors.New("pds: verification policy binding is missing")
	ErrEvidenceNotQualified      = errors.New("pds: bound evidence set is not qualified")
	ErrBoundEvidenceMismatch     = errors.New("pds: stored evidence does not match the binding")
	ErrRuleExecutionFailed       = errors.New("pds: rule operator execution failed")
	ErrPartialRuleOutcomes       = errors.New("pds: evaluation already contains a partial rule outcome set")
)

type EvidenceReader interface {
	Find(context.Context, uuid.UUID) (evidence.Snapshot, error)
}

// RuleInput is a defensive copy of the exact qualified Evidence Set bound to
// one Evaluation. Operators must be deterministic and side-effect free.
type RuleInput struct {
	EvaluationID  uuid.UUID
	SessionID     uuid.UUID
	PolicyID      string
	PolicyVersion string
	PolicyHash    string
	Evidence      []evidence.Snapshot
}

type RuleDecision struct {
	Status      evaluation.RuleOutcomeStatus
	ReasonCodes []evaluation.ReasonCode
}

type RuleOperator interface {
	RuleID() string
	Evaluate(context.Context, RuleInput) (RuleDecision, error)
}

type RuleExecutionService struct {
	evaluations *Service
	evidence    EvidenceReader
	operators   map[string]RuleOperator
}

func NewRuleExecutionService(evaluations *Service, reader EvidenceReader, operators []RuleOperator) (*RuleExecutionService, error) {
	if evaluations == nil {
		return nil, ErrEvaluationServiceRequired
	}
	if reader == nil {
		return nil, ErrEvidenceReaderRequired
	}
	registered := make(map[string]RuleOperator, len(operators))
	for _, operator := range operators {
		if operator == nil {
			return nil, ErrRuleOperatorRequired
		}
		id := strings.TrimSpace(operator.RuleID())
		if id == "" {
			return nil, ErrRuleOperatorRequired
		}
		if _, found := registered[id]; found {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateRuleOperator, id)
		}
		registered[id] = operator
	}
	return &RuleExecutionService{evaluations: evaluations, evidence: reader, operators: registered}, nil
}

// Execute runs every required operator in registration order and persists one
// atomic Rule Outcome batch. No outcomes are stored if preparation or any
// operator fails.
func (s *RuleExecutionService) Execute(ctx context.Context, evaluationID uuid.UUID) (evaluation.EvaluationSnapshot, error) {
	aggregate, err := s.evaluations.find(ctx, evaluationID)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	expectedVersion := aggregate.Version()
	snapshot, err := aggregate.Snapshot()
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	binding := snapshot.EvidenceBinding
	if binding == nil {
		return evaluation.EvaluationSnapshot{}, ErrEvidenceBindingMissing
	}
	if binding.Status != evaluation.EvidenceQualified {
		return evaluation.EvaluationSnapshot{}, ErrEvidenceNotQualified
	}
	policy := snapshot.PolicyBinding
	if policy == nil {
		return evaluation.EvaluationSnapshot{}, ErrPolicyBindingMissing
	}
	if len(snapshot.RuleOutcomes) > 0 {
		if len(aggregate.MissingRequiredRuleIDs()) == 0 {
			return snapshot, nil
		}
		return evaluation.EvaluationSnapshot{}, ErrPartialRuleOutcomes
	}
	for _, ruleID := range snapshot.RequiredRuleIDs {
		if s.operators[ruleID] == nil {
			return evaluation.EvaluationSnapshot{}, fmt.Errorf("%w: %s", ErrRuleOperatorMissing, ruleID)
		}
	}

	qualified := make([]evidence.Snapshot, 0, len(binding.Evidence))
	for _, reference := range binding.Evidence {
		if reference.Status != evaluation.EvidenceQualified {
			return evaluation.EvaluationSnapshot{}, ErrEvidenceNotQualified
		}
		stored, findErr := s.evidence.Find(ctx, reference.EvidenceID)
		if findErr != nil {
			return evaluation.EvaluationSnapshot{}, findErr
		}
		if stored.EvidenceID != reference.EvidenceID || stored.SessionID != snapshot.SessionID {
			return evaluation.EvaluationSnapshot{}, ErrBoundEvidenceMismatch
		}
		object, verifyErr := evidence.Rehydrate(stored)
		if verifyErr != nil {
			return evaluation.EvaluationSnapshot{}, verifyErr
		}
		qualified = append(qualified, object.Snapshot())
	}

	evaluatedAt := s.evaluations.now().UTC()
	outcomes := make([]evaluation.RuleOutcome, 0, len(snapshot.RequiredRuleIDs))
	for _, ruleID := range snapshot.RequiredRuleIDs {
		operatorEvidence, copyErr := copyEvidenceSnapshots(qualified)
		if copyErr != nil {
			return evaluation.EvaluationSnapshot{}, copyErr
		}
		decision, executeErr := s.operators[ruleID].Evaluate(ctx, RuleInput{
			EvaluationID: evaluationID, SessionID: snapshot.SessionID,
			PolicyID: policy.PolicyID, PolicyVersion: policy.Version,
			PolicyHash: policy.Hash, Evidence: operatorEvidence,
		})
		if executeErr != nil {
			return evaluation.EvaluationSnapshot{}, fmt.Errorf("%w: %s: %v", ErrRuleExecutionFailed, ruleID, executeErr)
		}
		outcomes = append(outcomes, evaluation.RuleOutcome{
			RuleID: ruleID, Status: decision.Status,
			ReasonCodes: append([]evaluation.ReasonCode(nil), decision.ReasonCodes...),
			EvaluatedAt: evaluatedAt,
		})
	}
	if err = aggregate.RecordRuleOutcomeBatch(outcomes, evaluatedAt); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if err = s.evaluations.save(ctx, aggregate, expectedVersion); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	return aggregate.Snapshot()
}

func copyEvidenceSnapshots(source []evidence.Snapshot) ([]evidence.Snapshot, error) {
	result := make([]evidence.Snapshot, 0, len(source))
	for _, snapshot := range source {
		object, err := evidence.Rehydrate(snapshot)
		if err != nil {
			return nil, err
		}
		result = append(result, object.Snapshot())
	}
	return result, nil
}

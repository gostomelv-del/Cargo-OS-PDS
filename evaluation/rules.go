package evaluation

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"time"
)

type RuleOutcome struct {
	RuleID      string
	Status      RuleOutcomeStatus
	ReasonCodes []ReasonCode
	EvaluatedAt time.Time
}
type RuleOutcomeRecordedEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	RuleID      string
	Status      RuleOutcomeStatus
	ReasonCodes []ReasonCode
	EvaluatedAt time.Time
	Version     uint64
}

func (e *EvaluationAggregate) RecordRuleOutcome(o RuleOutcome) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	normalized, err := normalizeRuleOutcome(o)
	if err != nil {
		return err
	}
	if e.startedAt == nil || normalized.EvaluatedAt.Before(*e.startedAt) {
		return ErrInvalidRuleOutcomeTimestamp
	}
	if len(e.requiredRuleIDs) > 0 && !e.IsRuleRequired(normalized.RuleID) {
		return fmt.Errorf("%w: %s", ErrUnknownRule, normalized.RuleID)
	}
	if existing, found := e.RuleOutcomeByID(normalized.RuleID); found {
		if ruleOutcomesEqual(existing, normalized) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrRuleOutcomeConflict, normalized.RuleID)
	}
	e.ruleOutcomes = append(e.ruleOutcomes, copyRuleOutcome(normalized))
	e.version++
	e.addDomainEvent(RuleOutcomeRecordedEvent{e.id, e.sessionID, normalized.RuleID, normalized.Status, copyReasonCodes(normalized.ReasonCodes), normalized.EvaluatedAt, e.version})
	return nil
}

func (e *EvaluationAggregate) RecordRuleOutcomes(outcomes []RuleOutcome) error {
	for _, outcome := range outcomes {
		if err := e.RecordRuleOutcome(outcome); err != nil {
			return err
		}
	}
	return nil
}

func (e *EvaluationAggregate) RuleOutcomes() []RuleOutcome {
	out := make([]RuleOutcome, len(e.ruleOutcomes))
	copy(out, e.ruleOutcomes)
	for i := range out {
		out[i].ReasonCodes = copyReasonCodes(out[i].ReasonCodes)
	}
	return out
}
type RequiredRuleRegisteredEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	RuleID       string
	RegisteredAt time.Time
	Version      uint64
}

func (e *EvaluationAggregate) RegisterRequiredRule(id string) error {
	return e.RegisterRequiredRuleAt(id, time.Now().UTC())
}

func (e *EvaluationAggregate) RegisterRequiredRuleAt(id string, registeredAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state.IsTerminal() {
		return ErrInvalidStateTransition
	}
	if registeredAt.IsZero() || registeredAt.Before(e.createdAt) {
		return ErrInvalidRuleOutcomeTimestamp
	}
	registeredAt = registeredAt.UTC()
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrRuleIDRequired
	}
	for _, x := range e.requiredRuleIDs {
		if x == id {
			return nil
		}
	}
	e.requiredRuleIDs = append(e.requiredRuleIDs, id)
	e.version++
	e.addDomainEvent(RequiredRuleRegisteredEvent{e.id, e.sessionID, id, registeredAt, e.version})
	return nil
}
func (e *EvaluationAggregate) MissingRequiredRuleIDs() []string {
	seen := map[string]bool{}
	for _, o := range e.ruleOutcomes {
		seen[o.RuleID] = true
	}
	var out []string
	for _, id := range e.requiredRuleIDs {
		if !seen[id] {
			out = append(out, id)
		}
	}
	return out
}
func (e *EvaluationAggregate) RequiredRulesComplete() bool {
	return len(e.MissingRequiredRuleIDs()) == 0
}
func (e *EvaluationAggregate) DeriveResult() (VerificationResult, []ReasonCode, error) {
	if !e.RequiredRulesComplete() {
		return ResultUnknown, nil, ErrRequiredRulesIncomplete
	}
	if len(e.ruleOutcomes) == 0 {
		return ResultUnknown, nil, ErrInvalidRuleOutcome
	}
	var reasons []ReasonCode
	result := ResultVerified
	for _, o := range e.ruleOutcomes {
		switch o.Status {
		case RuleOutcomeFail:
			result = ResultRejected
			reasons = append(reasons, o.ReasonCodes...)
		case RuleOutcomeInconclusive:
			if result != ResultRejected {
				result = ResultManualReview
			}
			reasons = append(reasons, o.ReasonCodes...)
		case RuleOutcomeWarning:
			if result == ResultVerified {
				result = ResultVerifiedWithException
			}
			reasons = append(reasons, o.ReasonCodes...)
		}
	}
	nr, err := normalizeReasonCodes(reasons)
	return result, nr, err
}

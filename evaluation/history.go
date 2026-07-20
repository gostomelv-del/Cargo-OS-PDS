package evaluation

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrCheckpointNotFound             = errors.New("evaluation: checkpoint not found")
	ErrCheckpointAlreadyExists        = errors.New("evaluation: checkpoint already exists")
	ErrEvaluationHistoryEntryNotFound = errors.New("evaluation: history entry not found")
	ErrEvaluationHistoryVersionExists = errors.New("evaluation: history version already exists")
	ErrInvalidEvaluationHistoryEntry  = errors.New("evaluation: invalid history entry")
	ErrHistoryCaptureTimeRequired     = errors.New("evaluation: history capture time is required")
	ErrMutationFunctionRequired       = errors.New("evaluation: mutation function is required")
)

type EvaluationCheckpoint struct {
	Name         string
	RuleOutcomes []RuleOutcome
	Version      uint64
	CreatedAt    time.Time
}

type EvaluationCheckpointCreatedEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Name         string
	CreatedAt    time.Time
	Version      uint64
}

type EvaluationRolledBackEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Checkpoint   string
	RolledBackAt time.Time
	Version      uint64
}

type EvaluationHistoryEntry struct {
	EvaluationID    uuid.UUID
	SessionID       uuid.UUID
	Version         uint64
	State           EvaluationState
	Result          VerificationResult
	ReasonCodes     []ReasonCode
	RequiredRuleIDs []string
	RuleOutcomes    []RuleOutcome
	RecordedAt      time.Time
}

type EvaluationHistoryRecordedEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Version      uint64
	RecordedAt   time.Time
}

func (e *EvaluationAggregate) CreateCheckpoint(name string, createdAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrRuleIDRequired
	}
	if createdAt.IsZero() {
		return ErrHistoryCaptureTimeRequired
	}
	createdAt = createdAt.UTC()
	if e.startedAt == nil || createdAt.Before(*e.startedAt) {
		return ErrInvalidEvaluationHistoryEntry
	}
	if e.checkpoints == nil {
		e.checkpoints = make(map[string]EvaluationCheckpoint)
	}
	if _, exists := e.checkpoints[name]; exists {
		return ErrCheckpointAlreadyExists
	}
	e.checkpoints[name] = EvaluationCheckpoint{Name: name, RuleOutcomes: copyRuleOutcomes(e.ruleOutcomes), Version: e.version, CreatedAt: createdAt}
	e.version++
	e.addDomainEvent(EvaluationCheckpointCreatedEvent{e.id, e.sessionID, name, createdAt, e.version})
	return nil
}

func (e *EvaluationAggregate) RollbackToCheckpoint(name string, rolledBackAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	name = strings.TrimSpace(name)
	cp, ok := e.checkpoints[name]
	if !ok {
		return ErrCheckpointNotFound
	}
	if rolledBackAt.IsZero() {
		return ErrHistoryCaptureTimeRequired
	}
	rolledBackAt = rolledBackAt.UTC()
	if e.startedAt == nil || rolledBackAt.Before(*e.startedAt) || rolledBackAt.Before(cp.CreatedAt) {
		return ErrInvalidEvaluationHistoryEntry
	}
	e.ruleOutcomes = copyRuleOutcomes(cp.RuleOutcomes)
	e.version++
	e.addDomainEvent(EvaluationRolledBackEvent{e.id, e.sessionID, name, rolledBackAt, e.version})
	return nil
}

func (e *EvaluationAggregate) Checkpoints() []EvaluationCheckpoint {
	if e == nil || len(e.checkpoints) == 0 {
		return nil
	}
	names := make([]string, 0, len(e.checkpoints))
	for n := range e.checkpoints {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]EvaluationCheckpoint, 0, len(names))
	for _, n := range names {
		cp := e.checkpoints[n]
		cp.RuleOutcomes = copyRuleOutcomes(cp.RuleOutcomes)
		out = append(out, cp)
	}
	return out
}

func (e *EvaluationAggregate) RecordHistory(recordedAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if recordedAt.IsZero() {
		return ErrHistoryCaptureTimeRequired
	}
	recordedAt = recordedAt.UTC()
	if recordedAt.Before(e.createdAt) {
		return ErrInvalidEvaluationHistoryEntry
	}
	for _, h := range e.history {
		if h.Version == e.version {
			return fmt.Errorf("%w: %d", ErrEvaluationHistoryVersionExists, e.version)
		}
	}
	entry := EvaluationHistoryEntry{EvaluationID: e.id, SessionID: e.sessionID, Version: e.version, State: e.state, Result: e.result, ReasonCodes: copyReasonCodes(e.reasonCodes), RequiredRuleIDs: append([]string(nil), e.requiredRuleIDs...), RuleOutcomes: copyRuleOutcomes(e.ruleOutcomes), RecordedAt: recordedAt}
	if err := validateEvaluationHistoryEntry(entry); err != nil {
		return err
	}
	e.history = append(e.history, copyEvaluationHistoryEntry(entry))
	e.addDomainEvent(EvaluationHistoryRecordedEvent{e.id, e.sessionID, e.version, recordedAt})
	return nil
}

func validateEvaluationHistoryEntry(h EvaluationHistoryEntry) error {
	if h.EvaluationID == uuid.Nil || h.SessionID == uuid.Nil || h.Version == 0 || h.RecordedAt.IsZero() || !h.Result.IsValid() {
		return ErrInvalidEvaluationHistoryEntry
	}
	switch h.State {
	case StateCreated, StateRunning, StateCompleted, StateCancelled, StateExpired:
	default:
		return ErrInvalidEvaluationHistoryEntry
	}
	return nil
}

func copyEvaluationHistoryEntry(h EvaluationHistoryEntry) EvaluationHistoryEntry {
	h.ReasonCodes = copyReasonCodes(h.ReasonCodes)
	h.RequiredRuleIDs = append([]string(nil), h.RequiredRuleIDs...)
	h.RuleOutcomes = copyRuleOutcomes(h.RuleOutcomes)
	return h
}
func (e *EvaluationAggregate) History() []EvaluationHistoryEntry {
	if e == nil {
		return nil
	}
	out := make([]EvaluationHistoryEntry, len(e.history))
	for i, h := range e.history {
		out[i] = copyEvaluationHistoryEntry(h)
	}
	return out
}
func (e *EvaluationAggregate) HistoryAtVersion(version uint64) (EvaluationHistoryEntry, error) {
	if e == nil {
		return EvaluationHistoryEntry{}, ErrInvalidEvaluationSnapshot
	}
	for _, h := range e.history {
		if h.Version == version {
			return copyEvaluationHistoryEntry(h), nil
		}
	}
	return EvaluationHistoryEntry{}, ErrEvaluationHistoryEntryNotFound
}

type evaluationMutableState struct {
	State                                          EvaluationState
	Result                                         VerificationResult
	ReasonCodes                                    []ReasonCode
	RequiredRuleIDs                                []string
	RuleOutcomes                                   []RuleOutcome
	StartedAt, CompletedAt, CancelledAt, ExpiredAt *time.Time
	Version                                        uint64
	Checkpoints                                    map[string]EvaluationCheckpoint
	History                                        []EvaluationHistoryEntry
	Events                                         []DomainEvent
}

func copyTimePointer(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}
func copyEvaluationCheckpoints(src map[string]EvaluationCheckpoint) map[string]EvaluationCheckpoint {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]EvaluationCheckpoint, len(src))
	for k, v := range src {
		v.RuleOutcomes = copyRuleOutcomes(v.RuleOutcomes)
		out[k] = v
	}
	return out
}
func copyEvaluationHistory(src []EvaluationHistoryEntry) []EvaluationHistoryEntry {
	if len(src) == 0 {
		return nil
	}
	out := make([]EvaluationHistoryEntry, len(src))
	for i, v := range src {
		out[i] = copyEvaluationHistoryEntry(v)
	}
	return out
}
func (e *EvaluationAggregate) captureMutableState() (evaluationMutableState, error) {
	if e == nil {
		return evaluationMutableState{}, ErrInvalidEvaluationSnapshot
	}
	return evaluationMutableState{e.state, e.result, copyReasonCodes(e.reasonCodes), append([]string(nil), e.requiredRuleIDs...), copyRuleOutcomes(e.ruleOutcomes), copyTimePointer(e.startedAt), copyTimePointer(e.completedAt), copyTimePointer(e.cancelledAt), copyTimePointer(e.expiredAt), e.version, copyEvaluationCheckpoints(e.checkpoints), copyEvaluationHistory(e.history), append([]DomainEvent(nil), e.domainEvents...)}, nil
}
func (e *EvaluationAggregate) restoreMutableState(s evaluationMutableState) {
	e.state = s.State
	e.result = s.Result
	e.reasonCodes = copyReasonCodes(s.ReasonCodes)
	e.requiredRuleIDs = append([]string(nil), s.RequiredRuleIDs...)
	e.ruleOutcomes = copyRuleOutcomes(s.RuleOutcomes)
	e.startedAt = copyTimePointer(s.StartedAt)
	e.completedAt = copyTimePointer(s.CompletedAt)
	e.cancelledAt = copyTimePointer(s.CancelledAt)
	e.expiredAt = copyTimePointer(s.ExpiredAt)
	e.version = s.Version
	e.checkpoints = copyEvaluationCheckpoints(s.Checkpoints)
	e.history = copyEvaluationHistory(s.History)
	e.domainEvents = append([]DomainEvent(nil), s.Events...)
}

// ApplyAtomicMutation executes a mutation and records history. If either step fails,
// all mutable aggregate state is restored.
func (e *EvaluationAggregate) ApplyAtomicMutation(occurredAt time.Time, mutation func(*EvaluationAggregate) error) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if mutation == nil {
		return ErrMutationFunctionRequired
	}
	before, err := e.captureMutableState()
	if err != nil {
		return err
	}
	if err = mutation(e); err != nil {
		e.restoreMutableState(before)
		return err
	}
	if err = e.RecordHistory(occurredAt); err != nil {
		e.restoreMutableState(before)
		return err
	}
	return nil
}

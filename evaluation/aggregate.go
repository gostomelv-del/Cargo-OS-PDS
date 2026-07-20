package evaluation

import (
	"github.com/google/uuid"
	"strings"
	"time"
)

type DomainEvent interface{}

type EvaluationCreatedEvent struct {
	EvaluationID, SessionID uuid.UUID
	CreatedAt               time.Time
	Version                 uint64
}
type EvaluationStartedEvent struct {
	EvaluationID, SessionID uuid.UUID
	StartedAt               time.Time
	Version                 uint64
}
type EvaluationCompletedEvent struct {
	EvaluationID, SessionID uuid.UUID
	Result                  VerificationResult
	CompletedAt             time.Time
	Version                 uint64
}
type EvaluationRejectedEvent struct {
	EvaluationID, SessionID uuid.UUID
	ReasonCodes             []ReasonCode
	CompletedAt             time.Time
	Version                 uint64
}
type EvaluationManualReviewRequiredEvent struct {
	EvaluationID, SessionID uuid.UUID
	ReasonCodes             []ReasonCode
	RequiredAt              time.Time
	Version                 uint64
}
type EvaluationSystemExceptionEvent struct {
	EvaluationID, SessionID uuid.UUID
	ReasonCodes             []ReasonCode
	OccurredAt              time.Time
	Version                 uint64
}
type EvaluationCancelledEvent struct {
	EvaluationID, SessionID uuid.UUID
	Reason                  string
	CancelledAt             time.Time
	Version                 uint64
}
type EvaluationExpiredEvent struct {
	EvaluationID, SessionID uuid.UUID
	ExpiredAt               time.Time
	Version                 uint64
}

type EvaluationAggregate struct {
	id, sessionID                                  uuid.UUID
	state                                          EvaluationState
	result                                         VerificationResult
	reasonCodes                                    []ReasonCode
	createdAt                                      time.Time
	startedAt, completedAt, cancelledAt, expiredAt *time.Time
	cancellationReason                             string
	version                                        uint64
	domainEvents                                   []DomainEvent
	ruleOutcomes                                   []RuleOutcome
	requiredRuleIDs                                []string
	checkpoints                                    map[string]EvaluationCheckpoint
	history                                        []EvaluationHistoryEntry
}

func NewEvaluation(id, sessionID uuid.UUID, createdAt time.Time) (*EvaluationAggregate, error) {
	if id == uuid.Nil {
		return nil, ErrEvaluationIDRequired
	}
	if sessionID == uuid.Nil {
		return nil, ErrSessionIDRequired
	}
	if createdAt.IsZero() {
		return nil, ErrInvalidEvaluationSnapshot
	}
	createdAt = createdAt.UTC()
	e := &EvaluationAggregate{id: id, sessionID: sessionID, state: StateCreated, result: ResultUnknown, createdAt: createdAt, version: 1}
	e.addDomainEvent(EvaluationCreatedEvent{id, sessionID, createdAt, 1})
	return e, nil
}
func NewEvaluationNow(sessionID uuid.UUID) (*EvaluationAggregate, error) {
	return NewEvaluation(uuid.New(), sessionID, time.Now().UTC())
}
func (e *EvaluationAggregate) Start(at time.Time) error {
	if e == nil || !e.state.CanTransitionTo(StateRunning) {
		return ErrInvalidStateTransition
	}
	if at.IsZero() || at.Before(e.createdAt) {
		return ErrInvalidStartTime
	}
	at = at.UTC()
	e.state = StateRunning
	e.startedAt = &at
	e.version++
	e.addDomainEvent(EvaluationStartedEvent{e.id, e.sessionID, at, e.version})
	return nil
}
func (e *EvaluationAggregate) StartNow() error { return e.Start(time.Now().UTC()) }
func (e *EvaluationAggregate) CompleteAt(result VerificationResult, reasons []ReasonCode, at time.Time) error {
	if e == nil || !e.state.CanTransitionTo(StateCompleted) {
		return ErrInvalidStateTransition
	}
	if at.IsZero() || e.startedAt == nil || at.Before(*e.startedAt) {
		return ErrInvalidCompletionTime
	}
	if !result.IsValid() || result == ResultUnknown {
		return ErrInvalidCompletionResult
	}
	if !e.RequiredRulesComplete() {
		return ErrRequiredRulesIncomplete
	}
	nr, err := normalizeReasonCodes(reasons)
	if err != nil {
		return err
	}
	if (result == ResultRejected || result == ResultManualReview || result == ResultSystemException || result == ResultVerifiedWithException) && len(nr) == 0 {
		return ErrInvalidCompletionResult
	}
	if (result == ResultVerified || result == ResultVerifiedWithException) && result == ResultVerified && len(nr) > 0 {
		return ErrInvalidCompletionResult
	}
	at = at.UTC()
	e.state = StateCompleted
	e.result = result
	e.reasonCodes = nr
	e.completedAt = &at
	e.version++
	switch result {
	case ResultRejected:
		e.addDomainEvent(EvaluationRejectedEvent{e.id, e.sessionID, copyReasonCodes(nr), at, e.version})
	case ResultManualReview:
		e.addDomainEvent(EvaluationManualReviewRequiredEvent{e.id, e.sessionID, copyReasonCodes(nr), at, e.version})
	case ResultSystemException:
		e.addDomainEvent(EvaluationSystemExceptionEvent{e.id, e.sessionID, copyReasonCodes(nr), at, e.version})
	default:
		e.addDomainEvent(EvaluationCompletedEvent{e.id, e.sessionID, result, at, e.version})
	}
	return nil
}
func (e *EvaluationAggregate) CompleteNow(r VerificationResult, reasons []ReasonCode) error {
	return e.CompleteAt(r, reasons, time.Now().UTC())
}
func (e *EvaluationAggregate) RequireManualReview(reasons []ReasonCode) error {
	return e.CompleteNow(ResultManualReview, reasons)
}
func (e *EvaluationAggregate) MarkSystemException(reasons []ReasonCode) error {
	return e.CompleteNow(ResultSystemException, reasons)
}
func (e *EvaluationAggregate) Cancel(reason string) error {
	if e == nil || e.state.IsTerminal() {
		return ErrInvalidStateTransition
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ErrCancellationReasonRequired
	}
	now := time.Now().UTC()
	e.state = StateCancelled
	e.cancelledAt = &now
	e.cancellationReason = reason
	e.version++
	e.addDomainEvent(EvaluationCancelledEvent{e.id, e.sessionID, reason, now, e.version})
	return nil
}
func (e *EvaluationAggregate) Expire(at time.Time) error {
	if e == nil || e.state.IsTerminal() {
		return ErrInvalidStateTransition
	}
	at = at.UTC()
	if at.Before(e.createdAt) {
		return ErrInvalidExpirationTime
	}
	e.state = StateExpired
	e.expiredAt = &at
	e.version++
	e.addDomainEvent(EvaluationExpiredEvent{e.id, e.sessionID, at, e.version})
	return nil
}
func (e *EvaluationAggregate) addDomainEvent(v DomainEvent) {
	e.domainEvents = append(e.domainEvents, v)
}
func (e *EvaluationAggregate) DomainEvents() []DomainEvent {
	return append([]DomainEvent(nil), e.domainEvents...)
}
func (e *EvaluationAggregate) ClearDomainEvents()         { e.domainEvents = nil }
func (e *EvaluationAggregate) ID() uuid.UUID              { return e.id }
func (e *EvaluationAggregate) SessionID() uuid.UUID       { return e.sessionID }
func (e *EvaluationAggregate) State() EvaluationState     { return e.state }
func (e *EvaluationAggregate) Result() VerificationResult { return e.result }
func (e *EvaluationAggregate) Version() uint64            { return e.version }
func (e *EvaluationAggregate) IsTerminal() bool           { return e.state.IsTerminal() }
func copyReasonCodes(v []ReasonCode) []ReasonCode         { return append([]ReasonCode(nil), v...) }
func normalizeReasonCodes(v []ReasonCode) ([]ReasonCode, error) {
	out := make([]ReasonCode, 0, len(v))
	seen := map[ReasonCode]struct{}{}
	for _, r := range v {
		c, err := NewReasonCode(r.String())
		if err != nil {
			return nil, err
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out, nil
}

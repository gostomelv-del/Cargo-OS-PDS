package evaluation

import (
	"time"

	"github.com/google/uuid"
)

// EventMetadata is the typed envelope shared by every evaluation domain event.
type EventMetadata struct {
	EventType    string
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Version      uint64
	OccurredAt   time.Time
}

func (e EvaluationCreatedEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationCreatedEvent", e.EvaluationID, e.SessionID, e.Version, e.CreatedAt}
}
func (e EvaluationStartedEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationStartedEvent", e.EvaluationID, e.SessionID, e.Version, e.StartedAt}
}
func (e EvaluationCompletedEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationCompletedEvent", e.EvaluationID, e.SessionID, e.Version, e.CompletedAt}
}
func (e EvaluationRejectedEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationRejectedEvent", e.EvaluationID, e.SessionID, e.Version, e.CompletedAt}
}
func (e EvaluationManualReviewRequiredEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationManualReviewRequiredEvent", e.EvaluationID, e.SessionID, e.Version, e.RequiredAt}
}
func (e EvaluationSystemExceptionEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationSystemExceptionEvent", e.EvaluationID, e.SessionID, e.Version, e.OccurredAt}
}
func (e EvaluationCancelledEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationCancelledEvent", e.EvaluationID, e.SessionID, e.Version, e.CancelledAt}
}
func (e EvaluationExpiredEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationExpiredEvent", e.EvaluationID, e.SessionID, e.Version, e.ExpiredAt}
}
func (e RuleOutcomeRecordedEvent) Metadata() EventMetadata {
	return EventMetadata{"RuleOutcomeRecordedEvent", e.EvaluationID, e.SessionID, e.Version, e.EvaluatedAt}
}
func (e RequiredRuleRegisteredEvent) Metadata() EventMetadata {
	return EventMetadata{"RequiredRuleRegisteredEvent", e.EvaluationID, e.SessionID, e.Version, e.RegisteredAt}
}
func (e EvidenceSetBoundEvent) Metadata() EventMetadata {
	return EventMetadata{"EvidenceSetBoundEvent", e.EvaluationID, e.SessionID, e.Version, e.Binding.QualifiedAt}
}
func (e RuleOutcomeBatchRecordedEvent) Metadata() EventMetadata {
	return EventMetadata{"RuleOutcomeBatchRecordedEvent", e.EvaluationID, e.SessionID, e.Version, e.RecordedAt}
}
func (e RuleOutcomeReplacedEvent) Metadata() EventMetadata {
	return EventMetadata{"RuleOutcomeReplacedEvent", e.EvaluationID, e.SessionID, e.Version, e.ReplacedAt}
}
func (e RuleOutcomeBatchReplacedEvent) Metadata() EventMetadata {
	return EventMetadata{"RuleOutcomeBatchReplacedEvent", e.EvaluationID, e.SessionID, e.Version, e.ReplacedAt}
}
func (e RuleOutcomeRemovedEvent) Metadata() EventMetadata {
	return EventMetadata{"RuleOutcomeRemovedEvent", e.EvaluationID, e.SessionID, e.Version, e.RemovedAt}
}
func (e RuleOutcomeBatchRemovedEvent) Metadata() EventMetadata {
	return EventMetadata{"RuleOutcomeBatchRemovedEvent", e.EvaluationID, e.SessionID, e.Version, e.RemovedAt}
}
func (e RuleOutcomesResetEvent) Metadata() EventMetadata {
	return EventMetadata{"RuleOutcomesResetEvent", e.EvaluationID, e.SessionID, e.Version, e.ResetAt}
}
func (e EvaluationCheckpointCreatedEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationCheckpointCreatedEvent", e.EvaluationID, e.SessionID, e.Version, e.CreatedAt}
}
func (e EvaluationRolledBackEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationRolledBackEvent", e.EvaluationID, e.SessionID, e.Version, e.RolledBackAt}
}
func (e EvaluationHistoryRecordedEvent) Metadata() EventMetadata {
	return EventMetadata{"EvaluationHistoryRecordedEvent", e.EvaluationID, e.SessionID, e.Version, e.RecordedAt}
}

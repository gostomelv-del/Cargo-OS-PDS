package evaluation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDomainEventMetadataAndOutboxEnvelope(t *testing.T) {
	at := time.Now().UTC()
	evaluationID := uuid.New()
	sessionID := uuid.New()
	events := []DomainEvent{
		EvaluationCreatedEvent{evaluationID, sessionID, at, 1},
		EvaluationStartedEvent{evaluationID, sessionID, at, 2},
		RuleOutcomeRecordedEvent{
			EvaluationID: evaluationID,
			SessionID:    sessionID,
			RuleID:       "weight",
			Status:       RuleOutcomePass,
			EvaluatedAt:  at,
			Version:      3,
		},
		EvaluationCompletedEvent{evaluationID, sessionID, ResultVerified, at, 4},
	}

	for _, event := range events {
		metadata := event.Metadata()
		if metadata.EventType == "" || metadata.EvaluationID != evaluationID || metadata.SessionID != sessionID {
			t.Fatalf("invalid metadata: %#v", metadata)
		}
		record, err := NewOutboxRecord(event, at)
		if err != nil {
			t.Fatal(err)
		}
		if record.EventType != metadata.EventType || record.AggregateID != evaluationID || record.SessionID != sessionID {
			t.Fatalf("outbox envelope mismatch: %#v", record)
		}
	}
}

type invalidMetadataEvent struct{}

func (invalidMetadataEvent) Metadata() EventMetadata { return EventMetadata{} }

func TestInvalidEventMetadataRejected(t *testing.T) {
	if _, err := NewOutboxRecord(invalidMetadataEvent{}, time.Now().UTC()); err == nil {
		t.Fatal("expected invalid metadata error")
	}
}

package pds

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
)

func TestServicePersistsLifecycleAndOutbox(t *testing.T) {
	now := time.Date(2026, 7, 20, 16, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	service := NewServiceWithStore(store, func() time.Time {
		now = now.Add(time.Second)
		return now
	})
	ctx := context.Background()

	created, err := service.Create(ctx, uuid.New(), []string{"weight"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Start(ctx, created.EvaluationID); err != nil {
		t.Fatal(err)
	}
	if _, err = service.RecordOutcome(ctx, created.EvaluationID, evaluation.RuleOutcome{
		RuleID: "weight", Status: evaluation.RuleOutcomePass,
	}); err != nil {
		t.Fatal(err)
	}
	trace, err := service.Complete(ctx, created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	if trace.Result != evaluation.ResultVerified {
		t.Fatalf("unexpected result: %s", trace.Result)
	}
	events := store.OutboxRecords()
	if len(events) != 5 {
		t.Fatalf("expected 5 lifecycle events, got %d", len(events))
	}
	for _, record := range events {
		if record.AggregateID != created.EvaluationID {
			t.Fatal("outbox event has wrong aggregate ID")
		}
	}
}

func TestServiceBindsQualificationIntoDecisionTrace(t *testing.T) {
	now := time.Date(2026, 7, 20, 16, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	service := NewServiceWithStore(store, func() time.Time { return now })
	sessionID := uuid.New()
	created, err := service.Create(context.Background(), sessionID, []string{"weight"})
	if err != nil {
		t.Fatal(err)
	}
	evidenceID := uuid.New()
	qualified := evidence.SessionQualificationResult{
		SessionID: sessionID, Status: evidence.QualificationQualified,
		EvaluatedAt: now, PolicyVersion: "qualification.v1",
		Evidence: []evidence.QualificationResult{{
			EvidenceID: evidenceID, Status: evidence.QualificationQualified,
			EvaluatedAt: now, PolicyVersion: "qualification.v1",
		}},
	}
	snapshot, err := service.BindEvidenceQualification(context.Background(), created.EvaluationID, qualified)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.EvidenceBinding == nil || snapshot.EvidenceBinding.Evidence[0].EvidenceID != evidenceID {
		t.Fatalf("qualification was not persisted: %#v", snapshot.EvidenceBinding)
	}
	trace, err := service.Trace(context.Background(), created.EvaluationID)
	if err != nil || trace.EvidenceBinding == nil || trace.EvidenceBinding.PolicyVersion != "qualification.v1" {
		t.Fatalf("qualification missing from trace: %#v, %v", trace, err)
	}
	if records := store.OutboxRecords(); records[len(records)-1].EventType != "EvidenceSetBoundEvent" {
		t.Fatalf("binding event missing from outbox: %#v", records)
	}
}

func TestMemoryStoreRejectsStaleWriter(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	aggregate, _ := evaluation.NewEvaluation(uuid.New(), uuid.New(), time.Now().UTC())
	snapshot, _ := aggregate.Snapshot()
	if err := store.SaveEvaluation(ctx, snapshot, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEvaluation(ctx, snapshot, snapshot.Version+1, nil); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("expected version conflict, got %v", err)
	}
}

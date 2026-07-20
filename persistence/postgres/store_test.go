package postgres

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
)

func completedSnapshot(t *testing.T) evaluation.EvaluationSnapshot {
	t.Helper()
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	aggregate, err := evaluation.NewEvaluation(uuid.New(), uuid.New(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err = aggregate.RegisterRequiredRuleAt("weight", base); err != nil {
		t.Fatal(err)
	}
	if err = aggregate.Start(base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = aggregate.RecordRuleOutcome(evaluation.RuleOutcome{
		RuleID: "weight", Status: evaluation.RuleOutcomePass, EvaluatedAt: base.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	result, reasons, err := aggregate.DeriveResult()
	if err != nil {
		t.Fatal(err)
	}
	if err = aggregate.CompleteAt(result, reasons, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := aggregate.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestSnapshotCodecRoundTrip(t *testing.T) {
	snapshot := completedSnapshot(t)
	payload, err := encodeSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(payload) {
		t.Fatal("snapshot is not valid JSON")
	}
	restored, err := decodeSnapshot(payload)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID() != snapshot.EvaluationID || restored.Version() != snapshot.Version {
		t.Fatal("snapshot identity or version changed")
	}
	if restored.Result() != evaluation.ResultVerified {
		t.Fatalf("unexpected result: %s", restored.Result())
	}
}

func TestInvalidSnapshotPayloadRejected(t *testing.T) {
	if _, err := decodeSnapshot([]byte("{")); err == nil {
		t.Fatal("expected invalid JSON error")
	}
	snapshot := completedSnapshot(t)
	snapshot.Version = 0
	if _, err := encodeSnapshot(snapshot); !errors.Is(err, evaluation.ErrSnapshotVersionRequired) {
		t.Fatalf("expected version validation error, got %v", err)
	}
}

func TestOutboxRecordValidation(t *testing.T) {
	now := time.Now().UTC()
	event := evaluation.EvaluationCreatedEvent{
		EvaluationID: uuid.New(),
		SessionID:    uuid.New(),
		CreatedAt:    now,
		Version:      1,
	}
	record, err := evaluation.NewOutboxRecord(event, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateOutboxRecord(record); err != nil {
		t.Fatal(err)
	}
	record.Payload = []byte("{")
	if err = validateOutboxRecord(record); !errors.Is(err, ErrInvalidOutboxRecord) {
		t.Fatalf("expected invalid outbox error, got %v", err)
	}
}

func TestNewStoreRejectsNilDatabase(t *testing.T) {
	if _, err := NewStore(nil); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database error, got %v", err)
	}
}

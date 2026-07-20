package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evidence"
)

func evidenceSnapshot(t *testing.T) evidence.Snapshot {
	t.Helper()
	observed := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	object, err := evidence.NewObject(evidence.Input{
		EvidenceID:        uuid.New(),
		SessionID:         uuid.New(),
		SourceID:          "scale-17",
		SourceType:        "WEIGHT_SENSOR",
		EvidenceType:      evidence.TypeWeight,
		ObservedAt:        observed,
		ReceivedAt:        observed.Add(time.Second),
		Payload:           json.RawMessage(`{"unit":"kg","value":25}`),
		SchemaVersion:     "evidence.v1",
		RuntimeVersion:    "cargoos-pds.dev",
		AcquisitionMethod: "MQTT",
	})
	if err != nil {
		t.Fatal(err)
	}
	return object.Snapshot()
}

func TestEvidenceCodecRoundTrip(t *testing.T) {
	snapshot := evidenceSnapshot(t)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	object, err := decodeEvidenceSnapshot(payload)
	if err != nil {
		t.Fatal(err)
	}
	if object.Snapshot().Integrity.PayloadDigest != snapshot.Integrity.PayloadDigest {
		t.Fatal("evidence digest changed during round trip")
	}
}

func TestEvidenceRepositoryRequiresDatabase(t *testing.T) {
	var store *Store
	if err := store.SaveEvidence(context.Background(), evidenceSnapshot(t)); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
	if _, err := store.FindEvidence(context.Background(), uuid.New()); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
	if _, err := store.ListEvidenceBySession(context.Background(), uuid.New()); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
}

func TestDecodeEvidenceRejectsTampering(t *testing.T) {
	snapshot := evidenceSnapshot(t)
	snapshot.Payload = json.RawMessage(`{"unit":"kg","value":26}`)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeEvidenceSnapshot(payload); !errors.Is(err, evidence.ErrIntegrityMismatch) {
		t.Fatalf("expected integrity mismatch, got %v", err)
	}
}

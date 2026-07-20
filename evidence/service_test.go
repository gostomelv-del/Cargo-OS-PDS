package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestService(t *testing.T, repository Repository) (*Service, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	service, err := NewService(repository, ServiceConfig{
		SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test",
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, now
}

func serviceInput(now time.Time) Input {
	return Input{
		SessionID: uuid.New(), SourceID: "scale-17", SourceType: "WEIGHT_SENSOR",
		EvidenceType: TypeWeight, ObservedAt: now.Add(-time.Second),
		Payload: json.RawMessage(`{"unit":"kg","value":25}`), AcquisitionMethod: "HTTP",
	}
}

func TestServiceIngestAndFind(t *testing.T) {
	service, now := newTestService(t, NewMemoryRepository())
	snapshot, err := service.Ingest(context.Background(), serviceInput(now))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.EvidenceID == uuid.Nil || !snapshot.ReceivedAt.Equal(now) {
		t.Fatalf("service metadata was not assigned: %#v", snapshot)
	}
	if snapshot.Integrity.SchemaVersion != "evidence.v1" || snapshot.Integrity.RuntimeVersion != "cargoos-pds.test" {
		t.Fatalf("version metadata was not anchored: %#v", snapshot.Integrity)
	}
	found, err := service.Find(context.Background(), snapshot.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshotsEqual(snapshot, found) {
		t.Fatal("retrieved evidence differs from accepted evidence")
	}
}

func TestServiceIdempotencyAndConflict(t *testing.T) {
	repository := NewMemoryRepository()
	service, now := newTestService(t, repository)
	input := serviceInput(now)
	input.EvidenceID = uuid.New()
	first, err := service.Ingest(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now.Add(time.Minute) }
	second, err := service.Ingest(context.Background(), input)
	if err != nil || !snapshotsEqual(first, second) {
		t.Fatalf("identical ingestion was not idempotent: %v", err)
	}
	input.Payload = json.RawMessage(`{"unit":"kg","value":26}`)
	if _, err = service.Ingest(context.Background(), input); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestMemoryRepositoryDefensiveCopies(t *testing.T) {
	repository := NewMemoryRepository()
	object, err := NewObject(validInput())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := object.Snapshot()
	if err = repository.SaveEvidence(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Payload[0] = '['
	found, err := repository.FindEvidence(context.Background(), object.Snapshot().EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if found.Snapshot().Payload[0] != '{' {
		t.Fatal("caller mutation leaked into memory repository")
	}
}

func TestMemoryRepositoryConcurrentIdempotency(t *testing.T) {
	repository := NewMemoryRepository()
	object, err := NewObject(validInput())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := object.Snapshot()
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 16)
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- repository.SaveEvidence(context.Background(), snapshot)
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err = range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestServiceConfigurationValidation(t *testing.T) {
	repository := NewMemoryRepository()
	if _, err := NewService(nil, ServiceConfig{}); !errors.Is(err, ErrRepositoryRequired) {
		t.Fatalf("expected repository error, got %v", err)
	}
	if _, err := NewService(repository, ServiceConfig{RuntimeVersion: "v1"}); !errors.Is(err, ErrSchemaVersionRequired) {
		t.Fatalf("expected schema error, got %v", err)
	}
	if _, err := NewService(repository, ServiceConfig{SchemaVersion: "v1"}); !errors.Is(err, ErrRuntimeVersionRequired) {
		t.Fatalf("expected runtime error, got %v", err)
	}
}

func TestListBySessionIsDeterministic(t *testing.T) {
	repository := NewMemoryRepository()
	service, now := newTestService(t, repository)
	sessionID := uuid.New()
	inputs := []Input{serviceInput(now), serviceInput(now)}
	inputs[0].SessionID = sessionID
	inputs[0].ObservedAt = now.Add(-time.Second)
	inputs[1].SessionID = sessionID
	inputs[1].ObservedAt = now.Add(-2 * time.Second)
	for _, input := range inputs {
		if _, err := service.Ingest(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Ingest(context.Background(), serviceInput(now)); err != nil {
		t.Fatal(err)
	}
	listed, err := service.ListBySession(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || !listed[0].ObservedAt.Before(listed[1].ObservedAt) {
		t.Fatalf("session evidence is not deterministically ordered: %#v", listed)
	}
	listed[0].Payload[0] = '['
	again, err := service.ListBySession(context.Background(), sessionID)
	if err != nil || again[0].Payload[0] != '{' {
		t.Fatal("listed evidence was not defensively copied")
	}
}

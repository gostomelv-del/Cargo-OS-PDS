package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func setObject(t *testing.T, sessionID, evidenceID uuid.UUID, observedAt time.Time, value int) *Object {
	t.Helper()
	input := validInput()
	input.SessionID = sessionID
	input.EvidenceID = evidenceID
	input.ObservedAt = observedAt
	input.ReceivedAt = observedAt.Add(time.Second)
	input.Payload = json.RawMessage([]byte(`{"unit":"kg","value":` + strconv.Itoa(value) + `}`))
	object, err := NewObject(input)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func openQualifier(t *testing.T) *Qualifier {
	t.Helper()
	qualifier, err := NewQualifier(QualificationPolicy{Version: "qualification.v1"})
	if err != nil {
		t.Fatal(err)
	}
	return qualifier
}

func fixedUUID(t *testing.T, value string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestQualifySetRejectsLaterIdenticalObservationAsDuplicate(t *testing.T) {
	sessionID := uuid.New()
	observedAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	firstID := fixedUUID(t, "00000000-0000-0000-0000-000000000001")
	secondID := fixedUUID(t, "00000000-0000-0000-0000-000000000002")
	result, err := openQualifier(t).QualifySet(sessionID, []*Object{
		setObject(t, sessionID, secondID, observedAt, 2),
		setObject(t, sessionID, firstID, observedAt, 2),
	}, observedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != QualificationRejected || result.Evidence[0].EvidenceID != firstID || result.Evidence[0].Status != QualificationQualified {
		t.Fatalf("unexpected canonical observation: %#v", result)
	}
	if result.Evidence[1].Status != QualificationRejected || result.Evidence[1].Reasons[0].Code != ReasonDuplicateObservation {
		t.Fatalf("duplicate was not rejected: %#v", result.Evidence[1])
	}
}

func TestQualifySetRejectsEveryConflictingObservation(t *testing.T) {
	sessionID := uuid.New()
	observedAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	result, err := openQualifier(t).QualifySet(sessionID, []*Object{
		setObject(t, sessionID, uuid.New(), observedAt, 2),
		setObject(t, sessionID, uuid.New(), observedAt, 3),
	}, observedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, qualified := range result.Evidence {
		if qualified.Status != QualificationRejected || qualified.Reasons[0].Code != ReasonConflictingObservation {
			t.Fatalf("conflict was not rejected: %#v", result)
		}
	}
}

func TestQualifySetReportsEmptySetUnavailable(t *testing.T) {
	result, err := openQualifier(t).QualifySet(uuid.New(), nil, time.Now())
	if err != nil || result.Status != QualificationUnavailable || result.Reasons[0].Code != ReasonEvidenceUnavailable {
		t.Fatalf("unexpected empty-set result: %#v, %v", result, err)
	}
}

func TestServiceQualifiesRepositorySession(t *testing.T) {
	repository := NewMemoryRepository()
	service, now := newTestService(t, repository)
	sessionID := uuid.New()
	input := serviceInput(now)
	input.SessionID = sessionID
	if _, err := service.Ingest(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	result, err := service.QualifySession(context.Background(), sessionID, openQualifier(t))
	if err != nil || result.Status != QualificationQualified || len(result.Evidence) != 1 {
		t.Fatalf("unexpected service qualification: %#v, %v", result, err)
	}
	if _, err = service.QualifySession(context.Background(), sessionID, nil); !errors.Is(err, ErrQualifierRequired) {
		t.Fatalf("expected qualifier error, got %v", err)
	}
}

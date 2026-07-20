package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
)

func TestParseUUIDRoundTrip(t *testing.T) {
	want := uuid.New()
	got, err := parseUUID(want.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("UUID changed: %s != %s", got.String(), want.String())
	}
}

func TestParseUUIDRejectsMalformedValue(t *testing.T) {
	if _, err := parseUUID("not-a-uuid"); err == nil {
		t.Fatal("expected malformed UUID error")
	}
}

func TestRetryAndDeadLetterValidationBeforeDatabase(t *testing.T) {
	store := &Store{}
	record := evaluation.OutboxRecord{Status: evaluation.OutboxStatusPending}
	if err := store.ScheduleRetry(context.Background(), record, "worker"); !errors.Is(err, evaluation.ErrOutboxInvalidRetrySchedule) {
		t.Fatalf("expected retry validation error, got %v", err)
	}
	if err := store.MarkDeadLettered(context.Background(), record, "worker"); !errors.Is(err, evaluation.ErrOutboxAlreadyDeadLettered) {
		t.Fatalf("expected dead-letter validation error, got %v", err)
	}
}

func TestReleaseExpiredLocksValidatesTimestamp(t *testing.T) {
	store := &Store{}
	if _, err := store.ReleaseExpiredLocks(context.Background(), time.Time{}); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database error first, got %v", err)
	}
}

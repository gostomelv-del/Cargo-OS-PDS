package responsibility

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceAtomicallyCommitsTransferAndEvent(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	aggregate, assignedAt := responsibilityFixture(t)
	if err := repository.SaveResponsibility(ctx, aggregate.Snapshot(), 0); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	transferredAt := assignedAt.Add(time.Minute)
	snapshot, err := service.Transfer(ctx, "parcel-42", "warehouse-3", transferredAt)
	if err != nil {
		t.Fatal(err)
	}
	event, err := repository.FindTransfer(ctx, "parcel-42", 2)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != 2 || event.FromParticipantID != "vehicle-7" ||
		event.ToParticipantID != "warehouse-3" || !event.TransferredAt.Equal(transferredAt) {
		t.Fatalf("snapshot and event diverged: snapshot=%#v event=%#v", snapshot, event)
	}
}

func TestCommitTransferRejectsMismatchedEventWithoutMutation(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	aggregate, assignedAt := responsibilityFixture(t)
	initial := aggregate.Snapshot()
	if err := repository.SaveResponsibility(ctx, initial, 0); err != nil {
		t.Fatal(err)
	}
	if err := aggregate.Transfer("warehouse-3", assignedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	event, _ := aggregate.PendingTransfer()
	event.ToParticipantID = "hub-9"
	if err := repository.CommitTransfer(ctx, aggregate.Snapshot(), 1, event); !errors.Is(err, ErrInvalidTransferCommit) {
		t.Fatalf("expected invalid commit, got %v", err)
	}
	stored, err := repository.FindResponsibility(ctx, "parcel-42")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Snapshot() != initial {
		t.Fatalf("failed commit changed responsibility: %#v", stored.Snapshot())
	}
	if _, err = repository.FindTransfer(ctx, "parcel-42", 2); !errors.Is(err, ErrTransferNotFound) {
		t.Fatalf("failed commit appended event: %v", err)
	}
}

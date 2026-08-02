package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"cargoos/responsibility"
)

func TestResponsibilityRepositoryRequiresDatabase(t *testing.T) {
	var store *Store
	snapshot := responsibility.Snapshot{
		ObjectID: "parcel-42", ParticipantID: "vehicle-7", Version: 1,
		AssignedAt: time.Now().UTC(),
	}
	if err := store.SaveResponsibility(context.Background(), snapshot, 0); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
	if _, err := store.FindResponsibility(context.Background(), "parcel-42"); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
}

func TestPostgresResponsibilityRejectsStaleWriter(t *testing.T) {
	_, store := openIntegrationStore(t)
	ctx := context.Background()
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	objectID, err := responsibility.NewPhysicalObjectID("integration-parcel-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	assignedAt := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	aggregate, err := responsibility.New(objectID, "vehicle-7", assignedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveResponsibility(ctx, aggregate.Snapshot(), 0); err != nil {
		t.Fatal(err)
	}
	first, err := store.FindResponsibility(ctx, objectID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.FindResponsibility(ctx, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Transfer("warehouse-3", assignedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = second.Transfer("hub-9", assignedAt.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveResponsibility(ctx, first.Snapshot(), 1); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveResponsibility(ctx, second.Snapshot(), 1); !errors.Is(err, responsibility.ErrConcurrentModification) {
		t.Fatalf("expected stale-writer conflict, got %v", err)
	}
	stored, err := store.FindResponsibility(ctx, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot := stored.Snapshot(); snapshot.ParticipantID != "warehouse-3" || snapshot.Version != 2 {
		t.Fatalf("stale writer changed responsibility: %#v", snapshot)
	}
}

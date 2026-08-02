package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"cargoos/responsibility"
)

func TestPostgresResponsibilityOutboxLeaseRecoveryAndPublication(t *testing.T) {
	_, store := openIntegrationStore(t)
	ctx := context.Background()
	objectID := integrationResponsibilityID(t, "delivery")
	// Use an isolated historical window: ClaimResponsibilityTransfers correctly
	// sees every pending event in the shared integration database.
	assignedAt := time.Date(2000, 1, 1, 14, 0, 0, 0, time.UTC)
	aggregate, err := responsibility.New(objectID, "vehicle-7", assignedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveResponsibility(ctx, aggregate.Snapshot(), 0); err != nil {
		t.Fatal(err)
	}
	service, err := responsibility.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Transfer(ctx, objectID, "warehouse-3", assignedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	claimedAt := assignedAt.Add(2 * time.Minute)
	claim := responsibility.DeliveryClaim{
		Limit: 1, WorkerID: "publisher-1", ClaimedAt: claimedAt, LockDuration: time.Minute,
	}
	first, err := store.ClaimResponsibilityTransfers(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Event.ObjectID != objectID || first[0].Attempts != 1 {
		t.Fatalf("unexpected first claim: %#v", first)
	}
	claim.WorkerID = "publisher-2"
	claim.ClaimedAt = claimedAt.Add(30 * time.Second)
	second, err := store.ClaimResponsibilityTransfers(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("active lease was claimed twice: %#v", second)
	}
	if err = store.MarkResponsibilityTransferPublished(
		ctx, objectID, 2, "publisher-2", claimedAt.Add(40*time.Second),
	); !errors.Is(err, responsibility.ErrDeliveryConflict) {
		t.Fatalf("expected ownership conflict, got %v", err)
	}
	released, err := store.ReleaseExpiredResponsibilityLocks(ctx, claimedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if released != 1 {
		t.Fatalf("expected one released lease, got %d", released)
	}
	claim.ClaimedAt = claimedAt.Add(time.Minute)
	second, err = store.ClaimResponsibilityTransfers(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].Attempts != 2 || second[0].LockOwner != "publisher-2" {
		t.Fatalf("unexpected recovered claim: %#v", second)
	}
	if err = store.MarkResponsibilityTransferPublished(
		ctx, objectID, 2, "publisher-2", claimedAt.Add(2*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	claim.ClaimedAt = claimedAt.Add(3 * time.Minute)
	afterPublish, err := store.ClaimResponsibilityTransfers(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterPublish) != 0 {
		t.Fatalf("published event was reclaimed: %#v", afterPublish)
	}
}

func TestResponsibilityOutboxRequiresDatabase(t *testing.T) {
	var store *Store
	claim := responsibility.DeliveryClaim{
		Limit: 1, WorkerID: "publisher", ClaimedAt: time.Now().UTC(), LockDuration: time.Minute,
	}
	if _, err := store.ClaimResponsibilityTransfers(context.Background(), claim); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
}

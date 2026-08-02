package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"cargoos/responsibility"
)

func TestPostgresResponsibilityServiceCommitsSnapshotAndEvent(t *testing.T) {
	db, store := openIntegrationStore(t)
	ctx := context.Background()
	objectID := integrationResponsibilityID(t, "handover")
	assignedAt := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
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
	transferredAt := assignedAt.Add(time.Minute)
	if _, err = service.Transfer(ctx, objectID, "warehouse-3", transferredAt); err != nil {
		t.Fatal(err)
	}
	event, err := store.FindTransfer(ctx, objectID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if event.FromParticipantID != "vehicle-7" || event.ToParticipantID != "warehouse-3" ||
		!event.TransferredAt.Equal(transferredAt) {
		t.Fatalf("unexpected durable handover event: %#v", event)
	}
	if _, err = db.ExecContext(ctx, `
		UPDATE responsibility_handover_events
		   SET to_participant_id = 'tampered'
		 WHERE object_id = $1 AND version = 2
	`, objectID.String()); err == nil {
		t.Fatal("expected immutable handover facts to reject mutation")
	}
}

func TestPostgresHandoverEventFailureRollsBackResponsibility(t *testing.T) {
	db, store := openIntegrationStore(t)
	ctx := context.Background()
	objectID := integrationResponsibilityID(t, "rollback")
	assignedAt := time.Date(2026, 8, 2, 13, 0, 0, 0, time.UTC)
	aggregate, err := responsibility.New(objectID, "vehicle-7", assignedAt)
	if err != nil {
		t.Fatal(err)
	}
	initial := aggregate.Snapshot()
	if err = store.SaveResponsibility(ctx, initial, 0); err != nil {
		t.Fatal(err)
	}
	transferredAt := assignedAt.Add(time.Minute)
	if _, err = db.ExecContext(ctx, `
		INSERT INTO responsibility_handover_events (
			object_id, version, from_participant_id, to_participant_id,
			transferred_at, delivery_status
		) VALUES ($1, 2, 'vehicle-7', 'occupied-event', $2, 'PENDING')
	`, objectID.String(), transferredAt); err != nil {
		t.Fatal(err)
	}
	service, err := responsibility.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Transfer(ctx, objectID, "warehouse-3", transferredAt); err == nil {
		t.Fatal("expected duplicate event to abort handover")
	}
	stored, err := store.FindResponsibility(ctx, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Snapshot() != initial {
		t.Fatalf("failed event append changed responsibility: %#v", stored.Snapshot())
	}
	if _, err = store.FindTransfer(ctx, objectID, 3); !errors.Is(err, responsibility.ErrTransferNotFound) {
		t.Fatalf("unexpected transfer event after rollback: %v", err)
	}
}

func integrationResponsibilityID(t *testing.T, scenario string) responsibility.PhysicalObjectID {
	t.Helper()
	id, err := responsibility.NewPhysicalObjectID(
		"integration-" + scenario + "-" + time.Now().UTC().Format("20060102150405.000000000"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

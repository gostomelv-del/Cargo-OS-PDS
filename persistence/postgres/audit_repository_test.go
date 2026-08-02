package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"cargoos/audit"
)

func TestAuditRepositoryRequiresDatabase(t *testing.T) {
	var store *Store
	if err := store.AppendAuditEntry(context.Background(), audit.Entry{}); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
	if _, err := store.FindAuditHead(context.Background()); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
}

func TestPostgresAuditLedgerRejectsForkAndPreservesHead(t *testing.T) {
	_, store := openIntegrationStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	first, err := audit.NewEntry(1, audit.RecordEstimator, [32]byte{}, [32]byte{1}, at)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.AppendAuditEntry(ctx, first); err != nil {
		t.Fatal(err)
	}
	fork, err := audit.NewEntry(2, audit.RecordEvidenceBundle, [32]byte{9}, [32]byte{2}, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.AppendAuditEntry(ctx, fork); !errors.Is(err, audit.ErrLedgerConflict) {
		t.Fatalf("expected fork rejection, got %v", err)
	}
	second, err := audit.NewEntry(2, audit.RecordResponsibilityHandover, first.Root, [32]byte{2}, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.AppendAuditEntry(ctx, second); err != nil {
		t.Fatal(err)
	}
	head, err := store.FindAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != second.Sequence || head.Kind != second.Kind ||
		head.PreviousRoot != second.PreviousRoot || head.RecordRoot != second.RecordRoot ||
		head.Root != second.Root || !head.OccurredAt.Equal(second.OccurredAt) {
		t.Fatalf("unexpected audit head: %#v", head)
	}
}

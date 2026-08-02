package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/audit"
	"cargoos/evidencebundle"
)

func TestEvidenceBundleAuditRepositoryRequiresDatabase(t *testing.T) {
	var store *Store
	if err := store.SaveEvidenceBundleAudit(context.Background(), evidencebundle.AuditRecord{}); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
	if _, err := store.FindEvidenceBundleAudit(context.Background(), uuid.New()); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
}

func TestPostgresEvidenceBundleRootIsAtomicAndImmutable(t *testing.T) {
	db, store := openIntegrationStore(t)
	ctx := context.Background()
	record := evidencebundle.AuditRecord{
		BundleID: uuid.New(), EvaluationID: uuid.New(), SessionID: uuid.New(),
		GeneratedAt: time.Now().UTC().Truncate(time.Microsecond), BundleRoot: [32]byte{1, 2, 3},
	}
	if err := store.SaveEvidenceBundleAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	head, err := store.FindAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Kind != audit.RecordEvidenceBundle || head.RecordRoot != record.BundleRoot {
		t.Fatalf("Bundle Root was not bound to audit head: %#v", head)
	}
	if err = store.SaveEvidenceBundleAudit(ctx, record); !errors.Is(err, evidencebundle.ErrAuditRecordExists) {
		t.Fatalf("expected duplicate Bundle rejection, got %v", err)
	}
	headAfterDuplicate, err := store.FindAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if headAfterDuplicate.Sequence != head.Sequence || headAfterDuplicate.Root != head.Root {
		t.Fatalf("duplicate Bundle advanced audit ledger: %#v", headAfterDuplicate)
	}
	stored, err := store.FindEvidenceBundleAudit(ctx, record.BundleID)
	if err != nil {
		t.Fatal(err)
	}
	if stored != record {
		t.Fatalf("stored Bundle audit record changed: %#v", stored)
	}
	if _, err = db.ExecContext(ctx, `
		UPDATE evidence_bundle_audit_records SET bundle_root = bundle_root
		 WHERE bundle_id = $1
	`, record.BundleID.String()); err == nil {
		t.Fatal("expected immutable Bundle audit mutation rejection")
	}
}

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"cargoos/audit"
	"cargoos/evidencebundle"
)

func (s *Store) SaveEvidenceBundleAudit(ctx context.Context, record evidencebundle.AuditRecord) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	if err := record.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("postgres: begin Evidence Bundle audit transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err = lockAuditLedger(ctx, tx); err != nil {
		return err
	}
	entry, err := nextAuditEntryLocked(
		ctx, tx, audit.RecordEvidenceBundle, record.BundleRoot, record.GeneratedAt,
	)
	if err != nil {
		return err
	}
	if err = insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	written, err := tx.ExecContext(ctx, `
		INSERT INTO evidence_bundle_audit_records (
			bundle_id, evaluation_id, session_id, generated_at,
			bundle_root, audit_sequence
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (bundle_id) DO NOTHING
	`, record.BundleID.String(), record.EvaluationID.String(), record.SessionID.String(),
		record.GeneratedAt, record.BundleRoot[:], entry.Sequence)
	if err != nil {
		return fmt.Errorf("postgres: register Evidence Bundle audit record: %w", err)
	}
	affected, err := written.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect Evidence Bundle audit insert: %w", err)
	}
	if affected != 1 {
		return evidencebundle.ErrAuditRecordExists
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit Evidence Bundle audit transaction: %w", err)
	}
	return nil
}

func (s *Store) FindEvidenceBundleAudit(
	ctx context.Context,
	bundleID uuid.UUID,
) (evidencebundle.AuditRecord, error) {
	if s == nil || s.db == nil {
		return evidencebundle.AuditRecord{}, ErrDatabaseRequired
	}
	if bundleID == uuid.Nil {
		return evidencebundle.AuditRecord{}, evidencebundle.ErrAuditRecordInvalid
	}
	var record evidencebundle.AuditRecord
	var bundleRoot, auditRoot []byte
	var kind sql.NullInt64
	var storedBundleID, evaluationID, sessionID string
	err := s.db.QueryRowContext(ctx, `
		SELECT br.bundle_id, br.evaluation_id, br.session_id, br.generated_at,
		       br.bundle_root, al.record_kind, al.record_root
		  FROM evidence_bundle_audit_records br
		  LEFT JOIN audit_ledger al ON al.sequence = br.audit_sequence
		 WHERE br.bundle_id = $1
	`, bundleID.String()).Scan(
		&storedBundleID, &evaluationID, &sessionID, &record.GeneratedAt,
		&bundleRoot, &kind, &auditRoot,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return evidencebundle.AuditRecord{}, evidencebundle.ErrAuditRecordNotFound
	}
	if err != nil {
		return evidencebundle.AuditRecord{}, fmt.Errorf("postgres: find Evidence Bundle audit record: %w", err)
	}
	if len(bundleRoot) != 32 || len(auditRoot) != 32 || !kind.Valid ||
		audit.RecordKind(kind.Int64) != audit.RecordEvidenceBundle {
		return evidencebundle.AuditRecord{}, evidencebundle.ErrAuditRecordInvalid
	}
	record.BundleID, err = uuid.Parse(storedBundleID)
	if err != nil {
		return evidencebundle.AuditRecord{}, evidencebundle.ErrAuditRecordInvalid
	}
	record.EvaluationID, err = uuid.Parse(evaluationID)
	if err != nil {
		return evidencebundle.AuditRecord{}, evidencebundle.ErrAuditRecordInvalid
	}
	record.SessionID, err = uuid.Parse(sessionID)
	if err != nil {
		return evidencebundle.AuditRecord{}, evidencebundle.ErrAuditRecordInvalid
	}
	record.BundleRoot = ([32]byte)(bundleRoot)
	record.GeneratedAt = record.GeneratedAt.UTC()
	if record.BundleRoot != ([32]byte)(auditRoot) {
		return evidencebundle.AuditRecord{}, evidencebundle.ErrAuditRecordInvalid
	}
	if err = record.Validate(); err != nil || record.BundleID != bundleID {
		return evidencebundle.AuditRecord{}, evidencebundle.ErrAuditRecordInvalid
	}
	return record, nil
}

var _ evidencebundle.AuditRepository = (*Store)(nil)

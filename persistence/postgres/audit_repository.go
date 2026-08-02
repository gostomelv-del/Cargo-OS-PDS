package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"cargoos/audit"
)

func (s *Store) AppendAuditEntry(ctx context.Context, entry audit.Entry) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	if err := entry.Validate(); err != nil || entry.Sequence > math.MaxInt64 {
		return audit.ErrEntryNotCanonical
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("postgres: begin audit append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err = lockAuditLedger(ctx, tx); err != nil {
		return err
	}
	sequence, root, err := auditHeadLocked(ctx, tx)
	switch {
	case errors.Is(err, audit.ErrLedgerEmpty):
		if entry.Sequence != 1 || entry.PreviousRoot != ([32]byte{}) {
			return audit.ErrLedgerConflict
		}
	case err != nil:
		return err
	case entry.Sequence != sequence+1 || entry.PreviousRoot != root:
		return audit.ErrLedgerConflict
	}
	if err = insertAuditEntry(ctx, tx, entry); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit audit append: %w", err)
	}
	return nil
}

func lockAuditLedger(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `LOCK TABLE audit_ledger IN EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("postgres: lock audit ledger: %w", err)
	}
	return nil
}

func auditHeadLocked(ctx context.Context, tx *sql.Tx) (uint64, [32]byte, error) {
	var sequence uint64
	var encodedRoot []byte
	err := tx.QueryRowContext(ctx, `
		SELECT sequence, root FROM audit_ledger ORDER BY sequence DESC LIMIT 1
	`).Scan(&sequence, &encodedRoot)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, [32]byte{}, audit.ErrLedgerEmpty
	}
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("postgres: read audit head: %w", err)
	}
	if len(encodedRoot) != 32 {
		return 0, [32]byte{}, audit.ErrEntryNotCanonical
	}
	return sequence, ([32]byte)(encodedRoot), nil
}

func nextAuditEntryLocked(
	ctx context.Context,
	tx *sql.Tx,
	kind audit.RecordKind,
	recordRoot [32]byte,
	occurredAt time.Time,
) (audit.Entry, error) {
	sequence, previousRoot, err := auditHeadLocked(ctx, tx)
	if errors.Is(err, audit.ErrLedgerEmpty) {
		return audit.NewEntry(1, kind, [32]byte{}, recordRoot, occurredAt)
	}
	if err != nil {
		return audit.Entry{}, err
	}
	if sequence >= math.MaxInt64 {
		return audit.Entry{}, audit.ErrSequenceInvalid
	}
	return audit.NewEntry(sequence+1, kind, previousRoot, recordRoot, occurredAt)
}

func insertAuditEntry(ctx context.Context, tx *sql.Tx, entry audit.Entry) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_ledger (
			sequence, record_kind, previous_root, record_root, occurred_at, root
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, entry.Sequence, entry.Kind, entry.PreviousRoot[:], entry.RecordRoot[:],
		entry.OccurredAt, entry.Root[:]); err != nil {
		return fmt.Errorf("postgres: append audit entry: %w", err)
	}
	return nil
}

func (s *Store) FindAuditHead(ctx context.Context) (audit.Entry, error) {
	if s == nil || s.db == nil {
		return audit.Entry{}, ErrDatabaseRequired
	}
	var entry audit.Entry
	var previousRoot, recordRoot, root []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT sequence, record_kind, previous_root, record_root, occurred_at, root
		  FROM audit_ledger ORDER BY sequence DESC LIMIT 1
	`).Scan(&entry.Sequence, &entry.Kind, &previousRoot, &recordRoot, &entry.OccurredAt, &root)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.Entry{}, audit.ErrLedgerEmpty
	}
	if err != nil {
		return audit.Entry{}, fmt.Errorf("postgres: find audit head: %w", err)
	}
	if len(previousRoot) != 32 || len(recordRoot) != 32 || len(root) != 32 {
		return audit.Entry{}, audit.ErrEntryNotCanonical
	}
	entry.PreviousRoot = ([32]byte)(previousRoot)
	entry.RecordRoot = ([32]byte)(recordRoot)
	entry.Root = ([32]byte)(root)
	entry.OccurredAt = entry.OccurredAt.UTC()
	if err = entry.Validate(); err != nil {
		return audit.Entry{}, err
	}
	return entry, nil
}

var _ audit.Repository = (*Store)(nil)

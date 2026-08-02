package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

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
	if _, err = tx.ExecContext(ctx, `LOCK TABLE audit_ledger IN EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("postgres: lock audit ledger: %w", err)
	}
	var sequence uint64
	var root []byte
	err = tx.QueryRowContext(ctx, `
		SELECT sequence, root FROM audit_ledger ORDER BY sequence DESC LIMIT 1
	`).Scan(&sequence, &root)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if entry.Sequence != 1 || entry.PreviousRoot != ([32]byte{}) {
			return audit.ErrLedgerConflict
		}
	case err != nil:
		return fmt.Errorf("postgres: read audit head: %w", err)
	case len(root) != 32 || entry.Sequence != sequence+1 ||
		entry.PreviousRoot != ([32]byte)(root):
		return audit.ErrLedgerConflict
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO audit_ledger (
			sequence, record_kind, previous_root, record_root, occurred_at, root
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, entry.Sequence, entry.Kind, entry.PreviousRoot[:], entry.RecordRoot[:],
		entry.OccurredAt, entry.Root[:]); err != nil {
		return fmt.Errorf("postgres: append audit entry: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit audit append: %w", err)
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
	if err = entry.Validate(); err != nil {
		return audit.Entry{}, err
	}
	return entry, nil
}

var _ audit.Repository = (*Store)(nil)

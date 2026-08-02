package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"cargoos/responsibility"
)

func (s *Store) CommitTransfer(
	ctx context.Context,
	snapshot responsibility.Snapshot,
	expectedVersion uint64,
	event responsibility.TransferredEvent,
) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	normalized, err := responsibility.ValidateTransferCommit(snapshot, expectedVersion, event)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("postgres: begin responsibility transfer: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE responsibility_snapshots
		   SET participant_id = $2, version = $3, assigned_at = $4, updated_at = NOW()
		 WHERE object_id = $1 AND version = $5
		   AND participant_id = $6 AND assigned_at < $4
	`, normalized.ObjectID.String(), normalized.ParticipantID.String(), normalized.Version,
		normalized.AssignedAt, expectedVersion, event.FromParticipantID.String())
	if err = responsibilityWriteResult(result, err, "transfer"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO responsibility_handover_events (
			object_id, version, from_participant_id, to_participant_id,
			transferred_at, delivery_status
		) VALUES ($1, $2, $3, $4, $5, 'PENDING')
	`, event.ObjectID.String(), event.Version, event.FromParticipantID.String(),
		event.ToParticipantID.String(), event.TransferredAt.UTC()); err != nil {
		return fmt.Errorf("postgres: append responsibility handover event: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit responsibility transfer: %w", err)
	}
	return nil
}

func (s *Store) FindTransfer(
	ctx context.Context,
	objectID responsibility.PhysicalObjectID,
	version uint64,
) (responsibility.TransferredEvent, error) {
	if s == nil || s.db == nil {
		return responsibility.TransferredEvent{}, ErrDatabaseRequired
	}
	var event responsibility.TransferredEvent
	err := s.db.QueryRowContext(ctx, `
		SELECT object_id, from_participant_id, to_participant_id, transferred_at, version
		  FROM responsibility_handover_events
		 WHERE object_id = $1 AND version = $2
	`, objectID.String(), version).Scan(
		&event.ObjectID, &event.FromParticipantID, &event.ToParticipantID,
		&event.TransferredAt, &event.Version,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return responsibility.TransferredEvent{}, responsibility.ErrTransferNotFound
	}
	if err != nil {
		return responsibility.TransferredEvent{}, fmt.Errorf("postgres: find responsibility transfer: %w", err)
	}
	return event, nil
}

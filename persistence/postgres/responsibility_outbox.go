package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"cargoos/responsibility"
)

func (s *Store) ClaimResponsibilityTransfers(
	ctx context.Context,
	claim responsibility.DeliveryClaim,
) ([]responsibility.ClaimedTransfer, error) {
	if s == nil || s.db == nil {
		return nil, ErrDatabaseRequired
	}
	if err := claim.Validate(); err != nil {
		return nil, err
	}
	claimedAt := claim.ClaimedAt.UTC()
	lockUntil := claimedAt.Add(claim.LockDuration)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("postgres: begin responsibility claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		WITH ready AS (
			SELECT object_id, version
			  FROM responsibility_handover_events
			 WHERE delivery_status = 'PENDING'
			   AND transferred_at <= $2
			   AND (lock_until IS NULL OR lock_until <= $2)
			 ORDER BY transferred_at, object_id, version
			 FOR UPDATE SKIP LOCKED
			 LIMIT $1
		)
		UPDATE responsibility_handover_events AS event
		   SET lock_owner = $3, lock_until = $4, attempts = event.attempts + 1
		  FROM ready
		 WHERE event.object_id = ready.object_id AND event.version = ready.version
		RETURNING event.object_id, event.from_participant_id, event.to_participant_id,
		          event.transferred_at, event.version, event.attempts,
		          event.lock_owner, event.lock_until
	`, claim.Limit, claimedAt, strings.TrimSpace(claim.WorkerID), lockUntil)
	if err != nil {
		return nil, fmt.Errorf("postgres: claim responsibility transfers: %w", err)
	}
	defer rows.Close()
	claimed := make([]responsibility.ClaimedTransfer, 0, claim.Limit)
	for rows.Next() {
		var item responsibility.ClaimedTransfer
		if err = rows.Scan(
			&item.Event.ObjectID, &item.Event.FromParticipantID, &item.Event.ToParticipantID,
			&item.Event.TransferredAt, &item.Event.Version, &item.Attempts,
			&item.LockOwner, &item.LockUntil,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan claimed responsibility transfer: %w", err)
		}
		claimed = append(claimed, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate claimed responsibility transfers: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("postgres: commit responsibility claim: %w", err)
	}
	return claimed, nil
}

func (s *Store) MarkResponsibilityTransferPublished(
	ctx context.Context,
	objectID responsibility.PhysicalObjectID,
	version uint64,
	workerID string,
	publishedAt time.Time,
) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return responsibility.ErrWorkerIDRequired
	}
	if publishedAt.IsZero() {
		return responsibility.ErrPublicationTimeRequired
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE responsibility_handover_events
		   SET delivery_status = 'PUBLISHED', published_at = $4,
		       lock_owner = '', lock_until = NULL
		 WHERE object_id = $1 AND version = $2
		   AND delivery_status = 'PENDING' AND lock_owner = $3
		   AND transferred_at <= $4
	`, objectID.String(), version, workerID, publishedAt.UTC())
	return requireResponsibilityDeliveryUpdate(result, err, "publish")
}

func (s *Store) ReleaseExpiredResponsibilityLocks(ctx context.Context, at time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrDatabaseRequired
	}
	if at.IsZero() {
		return 0, responsibility.ErrClaimTimeRequired
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE responsibility_handover_events
		   SET lock_owner = '', lock_until = NULL
		 WHERE delivery_status = 'PENDING' AND lock_until <= $1
	`, at.UTC())
	if err != nil {
		return 0, fmt.Errorf("postgres: release responsibility locks: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("postgres: inspect released responsibility locks: %w", err)
	}
	return count, nil
}

func requireResponsibilityDeliveryUpdate(result sql.Result, err error, operation string) error {
	if err != nil {
		return fmt.Errorf("postgres: %s responsibility transfer: %w", operation, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect responsibility %s: %w", operation, err)
	}
	if affected != 1 {
		return responsibility.ErrDeliveryConflict
	}
	return nil
}

package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
)

func (s *Store) Insert(ctx context.Context, tx *sql.Tx, records []evaluation.OutboxRecord) error {
	if s == nil || s.db == nil || tx == nil {
		return ErrDatabaseRequired
	}
	return insertOutboxRecords(ctx, tx, records)
}

func (s *Store) ClaimReady(
	ctx context.Context,
	request evaluation.OutboxClaimRequest,
) ([]evaluation.OutboxRecord, error) {
	if s == nil || s.db == nil {
		return nil, ErrDatabaseRequired
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	claimedAt := request.ClaimedAt.UTC()
	lockUntil := claimedAt.Add(request.LockDuration)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("postgres: begin outbox claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		WITH claimed AS (
			SELECT event_id
			  FROM evaluation_outbox
			 WHERE (
				status = 'PENDING'
				OR (status = 'RETRY_SCHEDULED' AND next_attempt_at <= $2)
			 )
			   AND (lock_until IS NULL OR lock_until <= $2)
			 ORDER BY occurred_at, event_id
			 FOR UPDATE SKIP LOCKED
			 LIMIT $1
		)
		UPDATE evaluation_outbox AS event
		   SET status = 'PUBLISHING',
		       publishing_started_at = $2,
		       last_attempt_at = $2,
		       attempts = event.attempts + 1,
		       lock_owner = $3,
		       lock_until = $4
		  FROM claimed
		 WHERE event.event_id = claimed.event_id
		RETURNING
			event.event_id, event.aggregate_type, event.aggregate_id,
			event.session_id, event.aggregate_version, event.event_type,
			event.payload, event.status, event.occurred_at, event.created_at,
			event.publishing_started_at, event.published_at, event.next_attempt_at,
			event.last_attempt_at, event.dead_lettered_at, event.attempts,
			event.max_attempts, event.last_error, event.lock_owner, event.lock_until
	`, request.Limit, claimedAt, strings.TrimSpace(request.WorkerID), lockUntil)
	if err != nil {
		return nil, fmt.Errorf("postgres: claim outbox records: %w", err)
	}
	defer rows.Close()

	records := make([]evaluation.OutboxRecord, 0, request.Limit)
	for rows.Next() {
		record, scanErr := scanOutboxRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate claimed outbox records: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("postgres: commit outbox claim: %w", err)
	}
	return records, nil
}

func (s *Store) MarkPublished(
	ctx context.Context,
	id uuid.UUID,
	workerID string,
	publishedAt time.Time,
) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	if id == uuid.Nil {
		return evaluation.ErrOutboxRecordNotFound
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return evaluation.ErrOutboxWorkerIDRequired
	}
	if publishedAt.IsZero() {
		return evaluation.ErrOutboxPublishTimeRequired
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE evaluation_outbox
		   SET status = 'PUBLISHED',
		       published_at = $3,
		       next_attempt_at = NULL,
		       last_error = '',
		       lock_owner = '',
		       lock_until = NULL
		 WHERE event_id = $1
		   AND status = 'PUBLISHING'
		   AND lock_owner = $2
	`, id.String(), workerID, publishedAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: mark outbox published: %w", err)
	}
	return requireSingleOutboxUpdate(result)
}

func (s *Store) ScheduleRetry(
	ctx context.Context,
	record evaluation.OutboxRecord,
	workerID string,
) error {
	if record.Status != evaluation.OutboxStatusRetryScheduled || record.NextAttemptAt == nil {
		return evaluation.ErrOutboxInvalidRetrySchedule
	}
	return s.persistFailedRecord(ctx, record, workerID)
}

func (s *Store) MarkDeadLettered(
	ctx context.Context,
	record evaluation.OutboxRecord,
	workerID string,
) error {
	if record.Status != evaluation.OutboxStatusDeadLettered || record.DeadLetteredAt == nil {
		return evaluation.ErrOutboxAlreadyDeadLettered
	}
	return s.persistFailedRecord(ctx, record, workerID)
}

func (s *Store) persistFailedRecord(
	ctx context.Context,
	record evaluation.OutboxRecord,
	workerID string,
) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return evaluation.ErrOutboxWorkerIDRequired
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE evaluation_outbox
		   SET status = $3,
		       next_attempt_at = $4,
		       last_attempt_at = $5,
		       dead_lettered_at = $6,
		       attempts = $7,
		       last_error = $8,
		       lock_owner = '',
		       lock_until = NULL
		 WHERE event_id = $1
		   AND status = 'PUBLISHING'
		   AND lock_owner = $2
	`, record.ID.String(), workerID, record.Status, record.NextAttemptAt,
		record.LastAttemptAt, record.DeadLetteredAt, record.Attempts, record.LastError)
	if err != nil {
		return fmt.Errorf("postgres: persist outbox failure: %w", err)
	}
	return requireSingleOutboxUpdate(result)
}

func (s *Store) ReleaseExpiredLocks(ctx context.Context, at time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrDatabaseRequired
	}
	if at.IsZero() {
		return 0, evaluation.ErrOutboxFailureTimeRequired
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE evaluation_outbox
		   SET status = 'RETRY_SCHEDULED',
		       next_attempt_at = $1,
		       lock_owner = '',
		       lock_until = NULL
		 WHERE status = 'PUBLISHING'
		   AND lock_until <= $1
	`, at.UTC())
	if err != nil {
		return 0, fmt.Errorf("postgres: release expired outbox locks: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("postgres: inspect released outbox locks: %w", err)
	}
	return count, nil
}

func (s *Store) FindByID(ctx context.Context, id uuid.UUID) (evaluation.OutboxRecord, error) {
	if s == nil || s.db == nil {
		return evaluation.OutboxRecord{}, ErrDatabaseRequired
	}
	if id == uuid.Nil {
		return evaluation.OutboxRecord{}, evaluation.ErrOutboxRecordNotFound
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT
			event_id, aggregate_type, aggregate_id, session_id,
			aggregate_version, event_type, payload, status,
			occurred_at, created_at, publishing_started_at, published_at,
			next_attempt_at, last_attempt_at, dead_lettered_at, attempts,
			max_attempts, last_error, lock_owner, lock_until
		  FROM evaluation_outbox
		 WHERE event_id = $1
	`, id.String())
	record, err := scanOutboxRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return evaluation.OutboxRecord{}, evaluation.ErrOutboxRecordNotFound
	}
	return record, err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanOutboxRecord(scanner rowScanner) (evaluation.OutboxRecord, error) {
	var (
		record                                            evaluation.OutboxRecord
		id, aggregateID, sessionID, status                string
		publishingAt, publishedAt, nextAt, lastAt, deadAt sql.NullTime
		lockUntil                                         sql.NullTime
	)
	err := scanner.Scan(
		&id, &record.AggregateType, &aggregateID, &sessionID,
		&record.AggregateVersion, &record.EventType, &record.Payload, &status,
		&record.OccurredAt, &record.CreatedAt, &publishingAt, &publishedAt,
		&nextAt, &lastAt, &deadAt, &record.Attempts, &record.MaxAttempts,
		&record.LastError, &record.LockOwner, &lockUntil,
	)
	if err != nil {
		return evaluation.OutboxRecord{}, err
	}
	if record.ID, err = parseUUID(id); err != nil {
		return evaluation.OutboxRecord{}, err
	}
	if record.AggregateID, err = parseUUID(aggregateID); err != nil {
		return evaluation.OutboxRecord{}, err
	}
	if record.SessionID, err = parseUUID(sessionID); err != nil {
		return evaluation.OutboxRecord{}, err
	}
	record.Status = evaluation.OutboxStatus(status)
	record.PublishingStartedAt = nullTimePointer(publishingAt)
	record.PublishedAt = nullTimePointer(publishedAt)
	record.NextAttemptAt = nullTimePointer(nextAt)
	record.LastAttemptAt = nullTimePointer(lastAt)
	record.DeadLetteredAt = nullTimePointer(deadAt)
	record.LockUntil = nullTimePointer(lockUntil)
	if err = validateOutboxRecord(record); err != nil {
		return evaluation.OutboxRecord{}, err
	}
	return record, nil
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	at := value.Time.UTC()
	return &at
}

func requireSingleOutboxUpdate(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect outbox update: %w", err)
	}
	if affected != 1 {
		return evaluation.ErrOutboxConcurrentModification
	}
	return nil
}

func parseUUID(value string) (uuid.UUID, error) {
	compact := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(compact) != 32 {
		return uuid.Nil, fmt.Errorf("postgres: invalid UUID %q", value)
	}
	decoded, err := hex.DecodeString(compact)
	if err != nil {
		return uuid.Nil, fmt.Errorf("postgres: invalid UUID %q: %w", value, err)
	}
	var id uuid.UUID
	copy(id[:], decoded)
	return id, nil
}

var _ evaluation.OutboxRepository = (*Store)(nil)
var _ evaluation.OutboxPublisherRepository = (*Store)(nil)

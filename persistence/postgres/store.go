package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/pds"
)

var (
	ErrDatabaseRequired                 = errors.New("postgres: database is required")
	ErrEvaluationNotFound               = pds.ErrEvaluationNotFound
	ErrEvaluationConcurrentModification = pds.ErrConcurrentModification
	ErrInvalidExpectedVersion           = errors.New("postgres: invalid expected version")
	ErrInvalidOutboxRecord              = errors.New("postgres: invalid outbox record")
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrDatabaseRequired
	}
	return &Store{db: db}, nil
}

// SaveEvaluation atomically stores the aggregate snapshot and its pending
// outbox records. expectedVersion is zero only when inserting a new aggregate.
func (s *Store) SaveEvaluation(
	ctx context.Context,
	snapshot evaluation.EvaluationSnapshot,
	expectedVersion uint64,
	records []evaluation.OutboxRecord,
) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	payload, err := encodeSnapshot(snapshot)
	if err != nil {
		return err
	}
	if expectedVersion > 0 && snapshot.Version <= expectedVersion {
		return ErrInvalidExpectedVersion
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("postgres: begin evaluation transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err = persistSnapshot(ctx, tx, snapshot, expectedVersion, payload); err != nil {
		return err
	}
	if err = insertOutboxRecords(ctx, tx, records); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit evaluation transaction: %w", err)
	}
	return nil
}

func persistSnapshot(
	ctx context.Context,
	tx *sql.Tx,
	snapshot evaluation.EvaluationSnapshot,
	expectedVersion uint64,
	payload []byte,
) error {
	if expectedVersion == 0 {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO evaluations (
				evaluation_id, session_id, state, result, version, snapshot,
				created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		`, snapshot.EvaluationID.String(), snapshot.SessionID.String(), snapshot.State,
			snapshot.Result, snapshot.Version, payload, snapshot.CreatedAt)
		if err != nil {
			return fmt.Errorf("postgres: insert evaluation: %w", err)
		}
		return nil
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE evaluations
		   SET session_id = $2,
		       state = $3,
		       result = $4,
		       version = $5,
		       snapshot = $6,
		       updated_at = NOW()
		 WHERE evaluation_id = $1
		   AND version = $7
	`, snapshot.EvaluationID.String(), snapshot.SessionID.String(), snapshot.State,
		snapshot.Result, snapshot.Version, payload, expectedVersion)
	if err != nil {
		return fmt.Errorf("postgres: update evaluation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect evaluation update: %w", err)
	}
	if affected != 1 {
		return ErrEvaluationConcurrentModification
	}
	return nil
}

func insertOutboxRecords(ctx context.Context, tx *sql.Tx, records []evaluation.OutboxRecord) error {
	for _, record := range records {
		if err := validateOutboxRecord(record); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO evaluation_outbox (
				event_id, aggregate_type, aggregate_id, session_id,
				aggregate_version, event_type, payload, status,
				occurred_at, created_at, attempts, max_attempts
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`, record.ID.String(), record.AggregateType, record.AggregateID.String(),
			record.SessionID.String(), record.AggregateVersion, record.EventType,
			[]byte(record.Payload), record.Status, record.OccurredAt, record.CreatedAt,
			record.Attempts, record.MaxAttempts)
		if err != nil {
			return fmt.Errorf("postgres: insert outbox record: %w", err)
		}
	}
	return nil
}

func validateOutboxRecord(record evaluation.OutboxRecord) error {
	if record.ID == uuid.Nil || record.AggregateID == uuid.Nil || record.SessionID == uuid.Nil {
		return ErrInvalidOutboxRecord
	}
	if record.AggregateType == "" || record.AggregateVersion == 0 || record.EventType == "" {
		return ErrInvalidOutboxRecord
	}
	if !record.Status.IsValid() || record.OccurredAt.IsZero() || record.CreatedAt.IsZero() || !json.Valid(record.Payload) {
		return ErrInvalidOutboxRecord
	}
	return nil
}

func (s *Store) FindEvaluation(ctx context.Context, id uuid.UUID) (*evaluation.EvaluationAggregate, error) {
	if s == nil || s.db == nil {
		return nil, ErrDatabaseRequired
	}
	if id == uuid.Nil {
		return nil, evaluation.ErrEvaluationIDRequired
	}
	var payload []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT snapshot FROM evaluations WHERE evaluation_id = $1`,
		id.String(),
	).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEvaluationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find evaluation: %w", err)
	}
	return decodeSnapshot(payload)
}

func encodeSnapshot(snapshot evaluation.EvaluationSnapshot) ([]byte, error) {
	if _, err := evaluation.RehydrateEvaluation(snapshot); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode evaluation snapshot: %w", err)
	}
	return payload, nil
}

func decodeSnapshot(payload []byte) (*evaluation.EvaluationAggregate, error) {
	var snapshot evaluation.EvaluationSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, fmt.Errorf("postgres: decode evaluation snapshot: %w", err)
	}
	return evaluation.RehydrateEvaluation(snapshot)
}

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"cargoos/responsibility"
)

func (s *Store) SaveResponsibility(
	ctx context.Context,
	snapshot responsibility.Snapshot,
	expectedVersion uint64,
) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	aggregate, err := responsibility.Rehydrate(snapshot)
	if err != nil {
		return err
	}
	normalized := aggregate.Snapshot()
	if expectedVersion == ^uint64(0) || normalized.Version != expectedVersion+1 {
		return responsibility.ErrInvalidVersionTransition
	}
	if expectedVersion == 0 {
		result, insertErr := s.db.ExecContext(ctx, `
			INSERT INTO responsibility_snapshots (
				object_id, participant_id, version, assigned_at
			) VALUES ($1, $2, $3, $4)
			ON CONFLICT (object_id) DO NOTHING
		`, normalized.ObjectID.String(), normalized.ParticipantID.String(),
			normalized.Version, normalized.AssignedAt)
		return responsibilityWriteResult(result, insertErr, "insert")
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE responsibility_snapshots
		   SET participant_id = $2,
		       version = $3,
		       assigned_at = $4,
		       updated_at = NOW()
		 WHERE object_id = $1
		   AND version = $5
		   AND participant_id <> $2
		   AND assigned_at < $4
	`, normalized.ObjectID.String(), normalized.ParticipantID.String(),
		normalized.Version, normalized.AssignedAt, expectedVersion)
	return responsibilityWriteResult(result, err, "update")
}

func responsibilityWriteResult(result sql.Result, err error, operation string) error {
	if err != nil {
		return fmt.Errorf("postgres: %s responsibility: %w", operation, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect responsibility %s: %w", operation, err)
	}
	if affected != 1 {
		return responsibility.ErrConcurrentModification
	}
	return nil
}

func (s *Store) FindResponsibility(
	ctx context.Context,
	objectID responsibility.PhysicalObjectID,
) (*responsibility.Aggregate, error) {
	if s == nil || s.db == nil {
		return nil, ErrDatabaseRequired
	}
	validatedID, err := responsibility.NewPhysicalObjectID(objectID.String())
	if err != nil || validatedID != objectID {
		return nil, responsibility.ErrObjectIDRequired
	}
	var snapshot responsibility.Snapshot
	err = s.db.QueryRowContext(ctx, `
		SELECT object_id, participant_id, version, assigned_at
		  FROM responsibility_snapshots
		 WHERE object_id = $1
	`, objectID.String()).Scan(
		&snapshot.ObjectID, &snapshot.ParticipantID, &snapshot.Version, &snapshot.AssignedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, responsibility.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find responsibility: %w", err)
	}
	return responsibility.Rehydrate(snapshot)
}

var _ responsibility.Repository = (*Store)(nil)

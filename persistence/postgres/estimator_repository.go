package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"cargoos/estimator"
	"cargoos/responsibility"
)

func (s *Store) SaveEstimatorResult(ctx context.Context, result estimator.Result) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	if err := result.Validate(); err != nil || result.Replay.Sequence > math.MaxInt64 {
		return estimator.ErrResultInvalid
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("postgres: encode estimator result: %w", err)
	}
	written, err := s.db.ExecContext(ctx, `
		INSERT INTO estimator_results (
			object_id, sequence, observation_id, observation_digest,
			profile_id, profile_version, calibration_version,
			observed_at, completed_at, result
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (object_id, sequence) DO NOTHING
	`, result.Replay.ObjectID.String(), result.Replay.Sequence,
		result.Replay.ObservationID.String(), result.Replay.ObservationDigest[:],
		result.Replay.ProfileID, result.Replay.ProfileVersion,
		result.Replay.CalibrationVersion, result.Replay.ObservedAt,
		result.Replay.CompletedAt, payload)
	if err != nil {
		return fmt.Errorf("postgres: insert estimator result: %w", err)
	}
	affected, err := written.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect estimator result insert: %w", err)
	}
	if affected != 1 {
		return estimator.ErrResultAlreadyRecorded
	}
	return nil
}

func (s *Store) FindEstimatorResult(
	ctx context.Context,
	objectID responsibility.PhysicalObjectID,
	sequence uint64,
) (estimator.Result, error) {
	if s == nil || s.db == nil {
		return estimator.Result{}, ErrDatabaseRequired
	}
	validatedID, err := responsibility.NewPhysicalObjectID(objectID.String())
	if err != nil || validatedID != objectID || sequence == 0 || sequence > math.MaxInt64 {
		return estimator.Result{}, estimator.ErrResultInvalid
	}
	var payload []byte
	err = s.db.QueryRowContext(ctx, `
		SELECT result
		  FROM estimator_results
		 WHERE object_id = $1 AND sequence = $2
	`, objectID.String(), sequence).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return estimator.Result{}, estimator.ErrResultNotFound
	}
	if err != nil {
		return estimator.Result{}, fmt.Errorf("postgres: find estimator result: %w", err)
	}
	var result estimator.Result
	if err = json.Unmarshal(payload, &result); err != nil {
		return estimator.Result{}, fmt.Errorf("postgres: decode estimator result: %w", err)
	}
	if err = result.Validate(); err != nil || result.Replay.ObjectID != objectID ||
		result.Replay.Sequence != sequence {
		return estimator.Result{}, estimator.ErrResultInvalid
	}
	return result, nil
}

var _ estimator.Repository = (*Store)(nil)

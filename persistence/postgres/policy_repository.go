package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"cargoos/pds"
	"cargoos/policy"
)

// Add stores an immutable policy version. Repeating the exact version is
// idempotent; reusing its identity or overlapping an effective period fails.
func (s *Store) Add(ctx context.Context, version *policy.Version) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	if version == nil {
		return policy.ErrPolicyNotFound
	}
	snapshot := version.Snapshot()
	payload, err := encodePolicySnapshot(snapshot)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("postgres: begin policy transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, snapshot.PolicyID); err != nil {
		return fmt.Errorf("postgres: lock policy: %w", err)
	}
	var existingHash string
	err = tx.QueryRowContext(ctx, `
		SELECT policy_hash FROM policy_versions
		 WHERE policy_id = $1 AND version = $2
	`, snapshot.PolicyID, snapshot.Version).Scan(&existingHash)
	switch {
	case err == nil && existingHash == snapshot.Hash:
		return tx.Commit()
	case err == nil:
		return policy.ErrVersionConflict
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("postgres: inspect policy version: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO policy_versions (
			policy_id, version, schema_version, effective_from,
			effective_until, policy_hash, snapshot
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, snapshot.PolicyID, snapshot.Version, snapshot.SchemaVersion,
		snapshot.EffectiveFrom, snapshot.EffectiveUntil, snapshot.Hash, payload)
	if isExclusionViolation(err) {
		return policy.ErrEffectiveOverlap
	}
	if err != nil {
		return fmt.Errorf("postgres: insert policy version: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit policy transaction: %w", err)
	}
	return nil
}

// Resolve returns the single immutable version effective at the supplied time.
func (s *Store) Resolve(ctx context.Context, policyID string, at time.Time) (*policy.Version, error) {
	if s == nil || s.db == nil {
		return nil, ErrDatabaseRequired
	}
	if policyID == "" || at.IsZero() {
		return nil, policy.ErrPolicyNotFound
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT snapshot FROM policy_versions
		 WHERE policy_id = $1
		   AND effective_from <= $2
		   AND (effective_until IS NULL OR $2 < effective_until)
		 ORDER BY effective_from, version
		 LIMIT 2
	`, policyID, at.UTC())
	if err != nil {
		return nil, fmt.Errorf("postgres: resolve policy: %w", err)
	}
	defer rows.Close()
	var matches []*policy.Version
	for rows.Next() {
		var payload []byte
		if err = rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("postgres: scan policy: %w", err)
		}
		resolved, decodeErr := decodePolicySnapshot(payload)
		if decodeErr != nil {
			return nil, decodeErr
		}
		matches = append(matches, resolved)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate policies: %w", err)
	}
	switch len(matches) {
	case 0:
		return nil, policy.ErrPolicyNotFound
	case 1:
		return matches[0], nil
	default:
		return nil, policy.ErrAmbiguousPolicy
	}
}

func encodePolicySnapshot(snapshot policy.Snapshot) ([]byte, error) {
	if _, err := policy.Rehydrate(snapshot); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode policy snapshot: %w", err)
	}
	return payload, nil
}

func decodePolicySnapshot(payload []byte) (*policy.Version, error) {
	var snapshot policy.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, fmt.Errorf("postgres: decode policy snapshot: %w", err)
	}
	version, err := policy.Rehydrate(snapshot)
	if err != nil {
		return nil, fmt.Errorf("postgres: verify policy snapshot: %w", err)
	}
	return version, nil
}

func isExclusionViolation(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && databaseError.Code == "23P01"
}

var _ pds.PolicyResolver = (*Store)(nil)

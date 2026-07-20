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
func (s *Store) Add(ctx context.Context, activated *policy.ActivatedVersion) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	if activated == nil || activated.VerifiedVersion() == nil || activated.VerifiedVersion().Version() == nil {
		return policy.ErrPolicyNotFound
	}
	verified := activated.VerifiedVersion()
	snapshot := verified.Version().Snapshot()
	signature := verified.Signature()
	approval := activated.Approval()
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
	var existingVerified bool
	err = tx.QueryRowContext(ctx, `
		SELECT policy_hash, signature_value IS NOT NULL FROM policy_versions
		 WHERE policy_id = $1 AND version = $2
	`, snapshot.PolicyID, snapshot.Version).Scan(&existingHash, &existingVerified)
	versionExists := err == nil
	switch {
	case versionExists && existingHash == snapshot.Hash && existingVerified:
	case err == nil:
		return policy.ErrVersionConflict
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("postgres: inspect policy version: %w", err)
	}

	if !versionExists {
		_, err = tx.ExecContext(ctx, `
		INSERT INTO policy_versions (
			policy_id, version, schema_version, effective_from,
			effective_until, policy_hash, snapshot, signer_id, key_id,
			signature_algorithm, signed_at, signature_value
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, snapshot.PolicyID, snapshot.Version, snapshot.SchemaVersion,
			snapshot.EffectiveFrom, snapshot.EffectiveUntil, snapshot.Hash, payload,
			signature.SignerID, signature.KeyID, signature.Algorithm,
			signature.SignedAt, signature.Value)
		if isExclusionViolation(err) {
			return policy.ErrEffectiveOverlap
		}
		if err != nil {
			return fmt.Errorf("postgres: insert policy version: %w", err)
		}
	}
	if err = insertActivation(ctx, tx, snapshot, approval, activated.ActivatedAt()); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit policy transaction: %w", err)
	}
	return nil
}

func insertActivation(ctx context.Context, tx *sql.Tx, snapshot policy.Snapshot, approval policy.ApprovalRecord, activatedAt time.Time) error {
	var existingAt, existingApprovedAt time.Time
	var existingApprovedBy string
	err := tx.QueryRowContext(ctx, `
		SELECT event_at, approved_by, approved_at
		  FROM policy_lifecycle_events
		 WHERE policy_id = $1 AND version = $2 AND status = 'ACTIVE'
	`, snapshot.PolicyID, snapshot.Version).Scan(&existingAt, &existingApprovedBy, &existingApprovedAt)
	if err == nil {
		if existingAt.Equal(activatedAt) && existingApprovedBy == approval.ApprovedBy && existingApprovedAt.Equal(approval.ApprovedAt) {
			return nil
		}
		return policy.ErrInvalidLifecycleChange
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("postgres: inspect policy activation: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO policy_lifecycle_events (
			policy_id, version, status, event_at, approved_by, approved_at
		) VALUES ($1, $2, 'ACTIVE', $3, $4, $5)
	`, snapshot.PolicyID, snapshot.Version, activatedAt, approval.ApprovedBy, approval.ApprovedAt)
	if err != nil {
		return fmt.Errorf("postgres: activate policy: %w", err)
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
		SELECT versions.snapshot
		  FROM policy_versions AS versions
		  JOIN LATERAL (
		      SELECT status, event_at
		        FROM policy_lifecycle_events
		       WHERE policy_id = versions.policy_id AND version = versions.version
		       ORDER BY event_at DESC, event_id DESC
		       LIMIT 1
		  ) AS lifecycle ON TRUE
		 WHERE versions.policy_id = $1
		   AND versions.signature_value IS NOT NULL
		   AND lifecycle.status = 'ACTIVE'
		   AND lifecycle.event_at <= $2
		   AND versions.effective_from <= $2
		   AND (versions.effective_until IS NULL OR $2 < versions.effective_until)
		 ORDER BY versions.effective_from, versions.version
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

func (s *Store) Suspend(ctx context.Context, policyID, version string, at time.Time) error {
	return s.transitionPolicy(ctx, policyID, version, policy.LifecycleSuspended, at)
}

func (s *Store) Retire(ctx context.Context, policyID, version string, at time.Time) error {
	return s.transitionPolicy(ctx, policyID, version, policy.LifecycleRetired, at)
}

func (s *Store) transitionPolicy(ctx context.Context, policyID, version string, target policy.LifecycleStatus, at time.Time) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	if policyID == "" || version == "" || at.IsZero() {
		return policy.ErrInvalidLifecycleChange
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("postgres: begin lifecycle transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, policyID); err != nil {
		return fmt.Errorf("postgres: lock policy lifecycle: %w", err)
	}
	var current policy.LifecycleStatus
	var currentAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT status, event_at FROM policy_lifecycle_events
		 WHERE policy_id = $1 AND version = $2
		 ORDER BY event_at DESC, event_id DESC LIMIT 1
	`, policyID, version).Scan(&current, &currentAt)
	valid := (current == policy.LifecycleActive && (target == policy.LifecycleSuspended || target == policy.LifecycleRetired)) ||
		(current == policy.LifecycleSuspended && target == policy.LifecycleRetired)
	if err != nil || !valid || at.UTC().Before(currentAt) {
		return policy.ErrInvalidLifecycleChange
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO policy_lifecycle_events (policy_id, version, status, event_at)
		VALUES ($1, $2, $3, $4)
	`, policyID, version, target, at.UTC())
	if err != nil {
		return fmt.Errorf("postgres: transition policy lifecycle: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit lifecycle transaction: %w", err)
	}
	return nil
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

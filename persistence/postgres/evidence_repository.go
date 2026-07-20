package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"cargoos/evidence"
)

var (
	ErrEvidenceNotFound = evidence.ErrNotFound
	ErrEvidenceConflict = evidence.ErrConflict
)

// SaveEvidence appends an immutable Evidence Object. Repeating the exact same
// object is idempotent; reusing its identifier for different content fails.
func (s *Store) SaveEvidence(ctx context.Context, snapshot evidence.Snapshot) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	object, err := evidence.Rehydrate(snapshot)
	if err != nil {
		return err
	}
	normalized := object.Snapshot()
	payload, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("postgres: encode evidence: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO evidence_objects (
			evidence_id, session_id, source_id, source_type, evidence_type,
			observed_at, received_at, payload_digest, snapshot
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (evidence_id) DO NOTHING
	`, normalized.EvidenceID.String(), normalized.SessionID.String(), normalized.SourceID,
		normalized.SourceType, normalized.EvidenceType, normalized.ObservedAt,
		normalized.ReceivedAt, normalized.Integrity.PayloadDigest, payload)
	if err != nil {
		return fmt.Errorf("postgres: save evidence: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect evidence insert: %w", err)
	}
	if affected == 1 {
		return nil
	}

	var existingPayload []byte
	if err = s.db.QueryRowContext(ctx,
		`SELECT snapshot FROM evidence_objects WHERE evidence_id = $1`,
		normalized.EvidenceID.String(),
	).Scan(&existingPayload); err != nil {
		return fmt.Errorf("postgres: inspect existing evidence: %w", err)
	}
	existing, err := decodeEvidenceSnapshot(existingPayload)
	if err != nil {
		return err
	}
	if evidence.SameSubmission(existing.Snapshot(), normalized) {
		return nil
	}
	return ErrEvidenceConflict
}

func (s *Store) FindEvidence(ctx context.Context, id uuid.UUID) (*evidence.Object, error) {
	if s == nil || s.db == nil {
		return nil, ErrDatabaseRequired
	}
	if id == uuid.Nil {
		return nil, evidence.ErrEvidenceIDRequired
	}
	var payload []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT snapshot FROM evidence_objects WHERE evidence_id = $1`, id.String(),
	).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEvidenceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find evidence: %w", err)
	}
	return decodeEvidenceSnapshot(payload)
}

func decodeEvidenceSnapshot(payload []byte) (*evidence.Object, error) {
	var snapshot evidence.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, fmt.Errorf("postgres: decode evidence: %w", err)
	}
	object, err := evidence.Rehydrate(snapshot)
	if err != nil {
		return nil, fmt.Errorf("postgres: verify evidence: %w", err)
	}
	return object, nil
}

var _ evidence.Repository = (*Store)(nil)

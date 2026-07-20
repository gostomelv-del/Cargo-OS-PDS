package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"cargoos/policy"
)

func (s *Store) AddVerificationKey(ctx context.Context, key policy.VerificationKey) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	key.SignerID = strings.TrimSpace(key.SignerID)
	key.KeyID = strings.TrimSpace(key.KeyID)
	key.Algorithm = strings.TrimSpace(key.Algorithm)
	key.ValidFrom = key.ValidFrom.UTC()
	if key.SignerID == "" || key.KeyID == "" || key.Algorithm == "" || len(key.PublicKey) == 0 || key.ValidFrom.IsZero() {
		return policy.ErrVerificationKeyAbsent
	}
	if key.ValidUntil != nil && !key.ValidUntil.After(key.ValidFrom) {
		return policy.ErrKeyExpired
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO trusted_verification_keys (
			signer_id, key_id, algorithm, public_key, valid_from, valid_until
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (signer_id, key_id) DO NOTHING
	`, key.SignerID, key.KeyID, key.Algorithm, key.PublicKey, key.ValidFrom, key.ValidUntil)
	if err != nil {
		return fmt.Errorf("postgres: add verification key: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect verification key insert: %w", err)
	}
	if affected == 1 {
		return nil
	}
	existing, err := s.ResolveVerificationKey(ctx, key.SignerID, key.KeyID)
	if err != nil {
		return err
	}
	if sameStoredKey(existing, key) {
		return nil
	}
	return policy.ErrVerificationKeyConflict
}

func (s *Store) ResolveVerificationKey(ctx context.Context, signerID, keyID string) (policy.VerificationKey, error) {
	if s == nil || s.db == nil {
		return policy.VerificationKey{}, ErrDatabaseRequired
	}
	var key policy.VerificationKey
	var validUntil, revokedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT keys.signer_id, keys.key_id, keys.algorithm, keys.public_key,
		       keys.valid_from, keys.valid_until, revocations.revoked_at
		  FROM trusted_verification_keys AS keys
		  LEFT JOIN trust_key_revocations AS revocations
		    ON revocations.signer_id = keys.signer_id AND revocations.key_id = keys.key_id
		 WHERE keys.signer_id = $1 AND keys.key_id = $2
	`, strings.TrimSpace(signerID), strings.TrimSpace(keyID)).Scan(
		&key.SignerID, &key.KeyID, &key.Algorithm, &key.PublicKey,
		&key.ValidFrom, &validUntil, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return policy.VerificationKey{}, policy.ErrVerificationKeyAbsent
	}
	if err != nil {
		return policy.VerificationKey{}, fmt.Errorf("postgres: resolve verification key: %w", err)
	}
	key.ValidFrom = key.ValidFrom.UTC()
	if validUntil.Valid {
		value := validUntil.Time.UTC()
		key.ValidUntil = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time.UTC()
		key.RevokedAt = &value
	}
	return key, nil
}

func (s *Store) RevokeVerificationKey(ctx context.Context, signerID, keyID string, revokedAt time.Time) error {
	if s == nil || s.db == nil {
		return ErrDatabaseRequired
	}
	if revokedAt.IsZero() {
		return policy.ErrVerificationKeyAbsent
	}
	key, err := s.ResolveVerificationKey(ctx, signerID, keyID)
	if err != nil {
		return err
	}
	revokedAt = revokedAt.UTC()
	if revokedAt.Before(key.ValidFrom) {
		return policy.ErrKeyNotYetValid
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO trust_key_revocations (signer_id, key_id, revoked_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (signer_id, key_id) DO NOTHING
	`, key.SignerID, key.KeyID, revokedAt)
	if err != nil {
		return fmt.Errorf("postgres: revoke verification key: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: inspect key revocation: %w", err)
	}
	if affected == 1 {
		return nil
	}
	existing, err := s.ResolveVerificationKey(ctx, key.SignerID, key.KeyID)
	if err == nil && existing.RevokedAt != nil && existing.RevokedAt.Equal(revokedAt) {
		return nil
	}
	return policy.ErrVerificationKeyConflict
}

func sameStoredKey(left, right policy.VerificationKey) bool {
	return left.SignerID == right.SignerID && left.KeyID == right.KeyID && left.Algorithm == right.Algorithm &&
		bytes.Equal(left.PublicKey, right.PublicKey) && left.ValidFrom.Equal(right.ValidFrom) &&
		sameNullableTime(left.ValidUntil, right.ValidUntil)
}

func sameNullableTime(left, right *time.Time) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && left.Equal(*right))
}

var _ policy.TrustStore = (*Store)(nil)

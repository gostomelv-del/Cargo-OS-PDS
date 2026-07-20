package postgres

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"cargoos/migrations"
	"cargoos/policy"
)

func TestPostgresTrustStoreRotationAndRevocation(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, _ := NewStore(db)

	signedAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keyID := fmt.Sprintf("integration-key-%d", time.Now().UnixNano())
	key := policy.VerificationKey{
		SignerID: "integration-authority", KeyID: keyID, Algorithm: policy.AlgorithmEd25519,
		PublicKey: privateKey.Public().(ed25519.PublicKey), ValidFrom: signedAt.Add(-time.Hour),
	}
	if err = store.AddVerificationKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err = store.AddVerificationKey(ctx, key); err != nil {
		t.Fatalf("idempotent key add failed: %v", err)
	}
	conflict := key
	conflict.PublicKey = append([]byte(nil), key.PublicKey...)
	conflict.PublicKey[0] ^= 0xff
	if err = store.AddVerificationKey(ctx, conflict); !errors.Is(err, policy.ErrVerificationKeyConflict) {
		t.Fatalf("expected key conflict, got %v", err)
	}

	version, err := policy.NewVersion(policy.Input{
		PolicyID: "trust-store-integration", Version: "v1", SchemaVersion: "1",
		EffectiveFrom: signedAt, RequiredRuleIDs: []string{"weight"}, Document: json.RawMessage(`{"mode":"strict"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := policy.Signature{
		SignerID: key.SignerID, KeyID: key.KeyID, Algorithm: key.Algorithm, SignedAt: signedAt,
	}
	payload, _ := policy.SigningPayload(version, signature)
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	verifier, _ := policy.NewVerifier(store)
	if _, err = verifier.Verify(ctx, version, signature, signedAt); err != nil {
		t.Fatal(err)
	}
	revokedAt := signedAt.Add(time.Minute)
	if err = store.RevokeVerificationKey(ctx, key.SignerID, key.KeyID, revokedAt); err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeVerificationKey(ctx, key.SignerID, key.KeyID, revokedAt); err != nil {
		t.Fatalf("idempotent revocation failed: %v", err)
	}
	if _, err = verifier.Verify(ctx, version, signature, revokedAt); !errors.Is(err, policy.ErrKeyRevoked) {
		t.Fatalf("expected revoked key rejection, got %v", err)
	}
}

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

func testPolicyVersion(t *testing.T, policyID, version string, from time.Time, until *time.Time, document string) *policy.Version {
	t.Helper()
	value, err := policy.NewVersion(policy.Input{
		PolicyID: policyID, Version: version, SchemaVersion: "1",
		EffectiveFrom: from, EffectiveUntil: until,
		RequiredRuleIDs: []string{"weight", "seal"}, Document: json.RawMessage(document),
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testVerifiedPolicy(t *testing.T, version *policy.Version, signedAt time.Time) *policy.VerifiedVersion {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	trustStore, _ := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "policy-authority", KeyID: "test-key", Algorithm: policy.AlgorithmEd25519,
		PublicKey: privateKey.Public().(ed25519.PublicKey), ValidFrom: signedAt.Add(-time.Hour),
	})
	verifier, _ := policy.NewVerifier(trustStore)
	signature := policy.Signature{
		SignerID: "policy-authority", KeyID: "test-key", Algorithm: policy.AlgorithmEd25519,
		SignedAt: signedAt,
	}
	payload, _ := policy.SigningPayload(version, signature)
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	verified, err := verifier.Verify(context.Background(), version, signature)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func testActivatedPolicy(t *testing.T, version *policy.Version, at time.Time) *policy.ActivatedVersion {
	t.Helper()
	verified := testVerifiedPolicy(t, version, at.Add(-time.Minute))
	snapshot := version.Snapshot()
	activated, err := policy.Activate(verified, policy.ApprovalRecord{
		PolicyID: snapshot.PolicyID, Version: snapshot.Version, PolicyHash: snapshot.Hash,
		ApprovedBy: "policy-review-board", ApprovedAt: at.Add(-time.Second),
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	return activated
}

func TestPolicySnapshotCodecRoundTrip(t *testing.T) {
	from := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	version := testPolicyVersion(t, "cargo-transfer", "v1", from, nil, `{"limit":100}`)
	payload, err := encodePolicySnapshot(version.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodePolicySnapshot(payload)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Snapshot().Hash != version.Snapshot().Hash {
		t.Fatal("policy hash changed during round trip")
	}
}

func TestPostgresPolicyRegistry(t *testing.T) {
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
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}

	policyID := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	from := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	boundary := from.Add(24 * time.Hour)
	first := testPolicyVersion(t, policyID, "v1", from, &boundary, `{"limit":100}`)
	second := testPolicyVersion(t, policyID, "v2", boundary, nil, `{"limit":110}`)
	activatedFirst := testActivatedPolicy(t, first, from)
	if err = store.Add(ctx, activatedFirst); err != nil {
		t.Fatal(err)
	}
	if err = store.Add(ctx, activatedFirst); err != nil {
		t.Fatalf("idempotent add failed: %v", err)
	}
	if err = store.Add(ctx, testActivatedPolicy(t, second, boundary)); err != nil {
		t.Fatalf("adjacent period rejected: %v", err)
	}

	conflict := testPolicyVersion(t, policyID, "v1", from, &boundary, `{"limit":999}`)
	if err = store.Add(ctx, testActivatedPolicy(t, conflict, from)); !errors.Is(err, policy.ErrVersionConflict) {
		t.Fatalf("expected version conflict, got %v", err)
	}
	overlapUntil := boundary.Add(time.Hour)
	overlap := testPolicyVersion(t, policyID, "overlap", boundary.Add(-time.Hour), &overlapUntil, `{"limit":105}`)
	if err = store.Add(ctx, testActivatedPolicy(t, overlap, boundary)); !errors.Is(err, policy.ErrEffectiveOverlap) {
		t.Fatalf("expected effective overlap, got %v", err)
	}

	resolved, err := store.Resolve(ctx, policyID, boundary)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Snapshot().Version != "v2" {
		t.Fatalf("expected v2 at half-open boundary, got %s", resolved.Snapshot().Version)
	}
	if err = store.Suspend(ctx, policyID, "v2", boundary.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Resolve(ctx, policyID, boundary); !errors.Is(err, policy.ErrPolicyNotFound) {
		t.Fatalf("suspended policy remained resolvable: %v", err)
	}
	if err = store.Retire(ctx, policyID, "v2", boundary.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = store.Suspend(ctx, policyID, "v2", boundary.Add(3*time.Minute)); !errors.Is(err, policy.ErrInvalidLifecycleChange) {
		t.Fatalf("retired policy accepted transition: %v", err)
	}
	if _, err = store.Resolve(ctx, policyID, from.Add(-time.Nanosecond)); !errors.Is(err, policy.ErrPolicyNotFound) {
		t.Fatalf("expected policy not found, got %v", err)
	}
}

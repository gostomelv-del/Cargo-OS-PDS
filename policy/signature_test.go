package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestVerifierAdmitsTrustedEd25519Policy(t *testing.T) {
	signedAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	version, err := NewVersion(policyInput("1.0.0", signedAt, nil))
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	trustStore, err := NewMemoryTrustStore(VerificationKey{
		SignerID: "policy-authority", KeyID: "key-1", Algorithm: AlgorithmEd25519,
		PublicKey: privateKey.Public().(ed25519.PublicKey), ValidFrom: signedAt.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewVerifier(trustStore)
	signature := Signature{
		SignerID: "policy-authority", KeyID: "key-1", Algorithm: AlgorithmEd25519,
		SignedAt: signedAt,
	}
	payload, _ := SigningPayload(version, signature)
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	verified, err := verifier.Verify(context.Background(), version, signature)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Version().Snapshot().Hash != version.Snapshot().Hash {
		t.Fatal("verified policy identity changed")
	}
}

func TestVerifierRejectsTamperingUnknownAndRevokedKeys(t *testing.T) {
	signedAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	version, _ := NewVersion(policyInput("1.0.0", signedAt, nil))
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	revokedAt := signedAt.Add(-time.Minute)
	trustStore, _ := NewMemoryTrustStore(VerificationKey{
		SignerID: "policy-authority", KeyID: "revoked", Algorithm: AlgorithmEd25519,
		PublicKey: privateKey.Public().(ed25519.PublicKey), ValidFrom: signedAt.Add(-time.Hour), RevokedAt: &revokedAt,
	})
	verifier, _ := NewVerifier(trustStore)
	baseSignature := Signature{
		SignerID: "policy-authority", KeyID: "revoked", Algorithm: AlgorithmEd25519, SignedAt: signedAt,
	}
	payload, _ := SigningPayload(version, baseSignature)
	value := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if _, err := verifier.Verify(context.Background(), version, Signature{
		SignerID: "policy-authority", KeyID: "unknown", Algorithm: AlgorithmEd25519,
		SignedAt: signedAt, Value: value,
	}); !errors.Is(err, ErrVerificationKeyAbsent) {
		t.Fatalf("expected unknown key rejection, got %v", err)
	}
	if _, err := verifier.Verify(context.Background(), version, Signature{
		SignerID: "policy-authority", KeyID: "revoked", Algorithm: AlgorithmEd25519,
		SignedAt: signedAt, Value: value,
	}); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected revoked key rejection, got %v", err)
	}
	activeStore, _ := NewMemoryTrustStore(VerificationKey{
		SignerID: "policy-authority", KeyID: "revoked", Algorithm: AlgorithmEd25519,
		PublicKey: privateKey.Public().(ed25519.PublicKey), ValidFrom: signedAt.Add(-time.Hour),
	})
	activeVerifier, _ := NewVerifier(activeStore)
	tampered := value[:len(value)-4] + "AAAA"
	if _, err := activeVerifier.Verify(context.Background(), version, Signature{
		SignerID: "policy-authority", KeyID: "revoked", Algorithm: AlgorithmEd25519,
		SignedAt: signedAt, Value: tampered,
	}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected tampered signature rejection, got %v", err)
	}
	if _, err := activeVerifier.Verify(context.Background(), version, Signature{
		SignerID: "policy-authority", KeyID: "revoked", Algorithm: AlgorithmEd25519,
		SignedAt: signedAt.Add(time.Minute), Value: value,
	}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected signature-time substitution rejection, got %v", err)
	}
}

func TestRegistryRejectsUnverifiedVersion(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Add(context.Background(), nil); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected unverified policy rejection, got %v", err)
	}
}

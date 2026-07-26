package evidencebundle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"cargoos/policy"
)

func signedBundleFixture(t *testing.T) (Bundle, Signature, ed25519.PrivateKey, *policy.MemoryTrustStore) {
	t.Helper()
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	signingTime := bundle.Manifest.GeneratedAt.Add(time.Minute)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	store, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "bundle-authority", KeyID: "bundle-key-1", Algorithm: SignatureAlgorithm,
		PublicKey: privateKey.Public().(ed25519.PublicKey),
		ValidFrom: bundle.Manifest.GeneratedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := NewSignature(bundle, "bundle-authority", "bundle-key-1", signingTime)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := SigningPayload(bundle, signature)
	if err != nil {
		t.Fatal(err)
	}
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return bundle, signature, privateKey, store
}

func TestVerifySignatureAcceptsTrustedBundle(t *testing.T) {
	bundle, signature, _, store := signedBundleFixture(t)
	verified, err := VerifySignature(
		context.Background(), bundle, signature, store, signature.SigningTime.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Bundle().Manifest.BundleRoot != bundle.Manifest.BundleRoot ||
		verified.Signature() != signature {
		t.Fatal("verified bundle identity changed")
	}
	first, err := CanonicalSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalSignature(verified.Signature())
	if err != nil || string(first) != string(second) {
		t.Fatal("signature representation is not deterministic")
	}
}

func TestVerifySignatureRejectsBundleAndSignatureSubstitution(t *testing.T) {
	bundle, signature, _, store := signedBundleFixture(t)
	modified := copyBundle(bundle)
	modified.Objects[0].Payload[0] ^= 1
	if _, err := VerifySignature(
		context.Background(), modified, signature, store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, ErrObjectDigestMismatch) {
		t.Fatalf("expected object substitution rejection, got %v", err)
	}

	substituted := signature
	substituted.BundleRootHash = bundlePolicyHash
	if _, err := VerifySignature(
		context.Background(), bundle, substituted, store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, ErrBundleSignatureBinding) {
		t.Fatalf("expected root substitution rejection, got %v", err)
	}
	substituted = signature
	substituted.SignerID = "other-authority"
	if _, err := VerifySignature(
		context.Background(), bundle, substituted, store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, policy.ErrVerificationKeyAbsent) {
		t.Fatalf("expected signer substitution rejection, got %v", err)
	}
}

func TestVerifySignatureRejectsWrongKeyAndSigningTime(t *testing.T) {
	bundle, signature, _, _ := signedBundleFixture(t)
	otherKey := ed25519.NewKeyFromSeed([]byte("11111111111111111111111111111111"))
	store, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: signature.SignerID, KeyID: signature.KeyID, Algorithm: SignatureAlgorithm,
		PublicKey: otherKey.Public().(ed25519.PublicKey),
		ValidFrom: bundle.Manifest.GeneratedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifySignature(
		context.Background(), bundle, signature, store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, ErrBundleSignatureInvalid) {
		t.Fatalf("expected wrong key rejection, got %v", err)
	}

	if _, err = NewSignature(
		bundle, signature.SignerID, signature.KeyID, bundle.Manifest.GeneratedAt.Add(-time.Nanosecond),
	); !errors.Is(err, ErrBundleSigningTime) {
		t.Fatalf("expected pre-generation signing rejection, got %v", err)
	}
}

func TestVerifySignatureEnforcesKeyLifecycle(t *testing.T) {
	bundle, signature, privateKey, _ := signedBundleFixture(t)
	expiredAt := signature.SigningTime.Add(time.Minute)
	store, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: signature.SignerID, KeyID: signature.KeyID, Algorithm: SignatureAlgorithm,
		PublicKey: privateKey.Public().(ed25519.PublicKey),
		ValidFrom: bundle.Manifest.GeneratedAt, ValidUntil: &expiredAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifySignature(
		context.Background(), bundle, signature, store, expiredAt,
	); !errors.Is(err, policy.ErrKeyExpired) {
		t.Fatalf("expected expired key rejection, got %v", err)
	}

	revokedAt := signature.SigningTime.Add(time.Minute)
	revokedStore, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: signature.SignerID, KeyID: signature.KeyID, Algorithm: SignatureAlgorithm,
		PublicKey: privateKey.Public().(ed25519.PublicKey),
		ValidFrom: bundle.Manifest.GeneratedAt, RevokedAt: &revokedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifySignature(
		context.Background(), bundle, signature, revokedStore, revokedAt,
	); !errors.Is(err, policy.ErrKeyRevoked) {
		t.Fatalf("expected revoked key rejection, got %v", err)
	}
}

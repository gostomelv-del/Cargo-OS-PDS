package evidencebundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/policy"
)

func certificateFixture(t *testing.T) (IndependentVerificationReport, *TimestampedBundle, ed25519.PrivateKey, *policy.MemoryTrustStore) {
	t.Helper()
	bundle := independentlyVerifiableBundle(t)
	report, err := VerifyDecision(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	signingTime := bundle.Manifest.GeneratedAt.Add(time.Minute)
	bundlePublic, bundlePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundleStore, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "bundle-authority", KeyID: "bundle-key", Algorithm: SignatureAlgorithm,
		PublicKey: bundlePublic, ValidFrom: signingTime.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := NewSignature(bundle, "bundle-authority", "bundle-key", signingTime)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := SigningPayload(bundle, signature)
	if err != nil {
		t.Fatal(err)
	}
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(bundlePrivate, payload))
	verified, err := VerifySignature(context.Background(), bundle, signature, bundleStore, signingTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	timestampTime := signingTime.Add(time.Minute)
	timestampPublic, timestampPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	timestampStore, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "timestamp-authority", KeyID: "timestamp-key", Algorithm: TimestampAlgorithm,
		PublicKey: timestampPublic, ValidFrom: timestampTime.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	timestamp, err := NewTrustedTimestamp(verified, "timestamp-authority", "timestamp-key", "ts-cert-1", timestampTime)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = TimestampSigningPayload(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	timestamp.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(timestampPrivate, payload))
	timestamped, err := VerifyTrustedTimestamp(context.Background(), verified, timestamp, timestampStore, timestampTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	verifierPublic, verifierPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifierStore, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "offline-verifier", KeyID: "verifier-key", Algorithm: SignatureAlgorithm,
		PublicKey: verifierPublic, ValidFrom: timestampTime.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return report, timestamped, verifierPrivate, verifierStore
}

func signedCertificateFixture(t *testing.T) (VerificationCertificate, *TimestampedBundle, *policy.MemoryTrustStore) {
	t.Helper()
	report, timestamped, privateKey, store := certificateFixture(t)
	issuedAt := timestamped.Timestamp().IssuedAt.Add(time.Minute)
	certificate, err := NewVerificationCertificate(report, timestamped, uuid.New(), "offline-verifier", "verifier-key", issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := VerificationCertificateSigningPayload(certificate)
	if err != nil {
		t.Fatal(err)
	}
	certificate.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return certificate, timestamped, store
}

func TestVerificationCertificateIsCanonicalSignedAndReproducible(t *testing.T) {
	certificate, timestamped, store := signedCertificateFixture(t)
	verified, err := VerifyVerificationCertificate(context.Background(), timestamped, certificate, store, certificate.IssuedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	first, err := CanonicalVerificationCertificate(verified)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalVerificationCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || verified.StoredResult != verified.RecalculatedResult ||
		verified.StoredResult == evaluation.ResultUnknown {
		t.Fatal("verification certificate changed canonical identity")
	}
}

func TestVerificationCertificateRejectsBundleAndOutcomeSubstitution(t *testing.T) {
	certificate, timestamped, store := signedCertificateFixture(t)
	modified := certificate
	modified.BundleRoot = bundlePolicyHash
	if _, err := VerifyVerificationCertificate(context.Background(), timestamped, modified, store, certificate.IssuedAt.Add(time.Minute)); !errors.Is(err, ErrVerificationCertificateBinding) {
		t.Fatalf("expected Bundle Root substitution rejection, got %v", err)
	}
	modified = certificate
	modified.Outcomes = copyRecalculatedOutcomes(certificate.Outcomes)
	modified.Outcomes[0].Status = evaluation.RuleOutcomeFail
	if _, err := VerifyVerificationCertificate(context.Background(), timestamped, modified, store, certificate.IssuedAt.Add(time.Minute)); !errors.Is(err, ErrVerificationCertificateBinding) {
		t.Fatalf("expected outcome substitution rejection, got %v", err)
	}
}

func TestVerificationCertificateRejectsTimestampAndSignatureModification(t *testing.T) {
	certificate, timestamped, store := signedCertificateFixture(t)
	modified := certificate
	modified.TimestampHash = bundlePolicyHash
	if _, err := VerifyVerificationCertificate(context.Background(), timestamped, modified, store, certificate.IssuedAt.Add(time.Minute)); !errors.Is(err, ErrVerificationCertificateBinding) {
		t.Fatalf("expected timestamp substitution rejection, got %v", err)
	}
	modified = certificate
	modified.Value = modified.Value[:len(modified.Value)-4] + "AAAA"
	if _, err := VerifyVerificationCertificate(context.Background(), timestamped, modified, store, certificate.IssuedAt.Add(time.Minute)); !errors.Is(err, ErrVerificationCertificateInvalid) {
		t.Fatalf("expected signature modification rejection, got %v", err)
	}
}

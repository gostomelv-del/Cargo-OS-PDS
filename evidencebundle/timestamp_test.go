package evidencebundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"cargoos/policy"
)

func timestampedBundleFixture(t *testing.T) (*TimestampedBundle, *policy.MemoryTrustStore, *policy.MemoryTrustStore) {
	t.Helper()
	bundle, signature, _, bundleStore := signedBundleFixture(t)
	verified, err := VerifySignature(context.Background(), bundle, signature, bundleStore, signature.SigningTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := signature.SigningTime.Add(30 * time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	timestampStore, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "timestamp-authority", KeyID: "timestamp-key-1", Algorithm: TimestampAlgorithm,
		PublicKey: publicKey, ValidFrom: issuedAt.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	timestamp, err := NewTrustedTimestamp(verified, "timestamp-authority", "timestamp-key-1", "ts-000001", issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := TimestampSigningPayload(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	timestamp.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	timestamped, err := VerifyTrustedTimestamp(context.Background(), verified, timestamp, timestampStore, issuedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return timestamped, bundleStore, timestampStore
}

func TestTrustedTimestampBindsSignatureRootAndTime(t *testing.T) {
	timestamped, _, timestampStore := timestampedBundleFixture(t)
	verified := timestamped.VerifiedBundle()
	timestamp := timestamped.Timestamp()
	if timestamp.SignatureHash == "" || timestamp.BundleRootHash != verified.Bundle().Manifest.BundleRoot {
		t.Fatal("timestamp did not bind the signature and Bundle Root")
	}

	modified := timestamp
	if modified.SignatureHash[0] == '0' {
		modified.SignatureHash = "1" + modified.SignatureHash[1:]
	} else {
		modified.SignatureHash = "0" + modified.SignatureHash[1:]
	}
	if _, err := VerifyTrustedTimestamp(context.Background(), verified, modified, timestampStore, timestamp.IssuedAt.Add(time.Minute)); !errors.Is(err, ErrBundleTimestampBinding) {
		t.Fatalf("expected signature binding rejection, got %v", err)
	}

	modified = timestamp
	modified.IssuedAt = verified.Signature().SigningTime.Add(-time.Nanosecond)
	if _, err := VerifyTrustedTimestamp(context.Background(), verified, modified, timestampStore, timestamp.IssuedAt.Add(time.Minute)); !errors.Is(err, ErrBundleTimestampTime) {
		t.Fatalf("expected chronology rejection, got %v", err)
	}
}

func TestTrustedTimestampEnforcesAuthorityKeyLifecycle(t *testing.T) {
	timestamped, _, _ := timestampedBundleFixture(t)
	verified := timestamped.VerifiedBundle()
	timestamp := timestamped.Timestamp()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := timestamp.IssuedAt
	store, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: timestamp.AuthorityID, KeyID: timestamp.KeyID, Algorithm: TimestampAlgorithm,
		PublicKey: publicKey, ValidFrom: timestamp.IssuedAt.Add(-time.Hour), RevokedAt: &revokedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyTrustedTimestamp(context.Background(), verified, timestamp, store, timestamp.IssuedAt.Add(time.Minute)); !errors.Is(err, policy.ErrKeyRevoked) {
		t.Fatalf("expected timestamp authority revocation rejection, got %v", err)
	}
}

func TestTimestampedArchiveRoundTripIsDeterministicAndTrusted(t *testing.T) {
	timestamped, bundleStore, timestampStore := timestampedBundleFixture(t)
	first, err := ExportTimestampedArchive(timestamped)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExportTimestampedArchive(timestamped)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("timestamped archive is not byte deterministic")
	}
	imported, err := ImportTimestampedArchive(context.Background(), first, bundleStore, timestampStore, timestamped.Timestamp().IssuedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if imported.Timestamp() != timestamped.Timestamp() {
		t.Fatal("timestamped archive changed timestamp identity")
	}
}

func TestTimestampedArchiveRejectsMissingModifiedAndNoncanonicalTimestamp(t *testing.T) {
	timestamped, bundleStore, timestampStore := timestampedBundleFixture(t)
	signed, err := ExportSignedArchive(timestamped.VerifiedBundle())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ImportTimestampedArchive(context.Background(), signed, bundleStore, timestampStore, timestamped.Timestamp().IssuedAt.Add(time.Minute)); !errors.Is(err, ErrBundleTimestampRequired) {
		t.Fatalf("expected missing timestamp rejection, got %v", err)
	}

	payload, err := ExportTimestampedArchive(timestamped)
	if err != nil {
		t.Fatal(err)
	}
	entries := readTestArchive(t, payload)
	entries[TimestampEntryPath][len(entries[TimestampEntryPath])-2] ^= 1
	if _, err = ImportTimestampedArchive(context.Background(), writeTestArchive(t, entries), bundleStore, timestampStore, timestamped.Timestamp().IssuedAt.Add(time.Minute)); err == nil {
		t.Fatal("expected modified timestamp rejection")
	}

	entries = readTestArchive(t, payload)
	entries[TimestampEntryPath] = append([]byte(" "), entries[TimestampEntryPath]...)
	if _, err = ImportTimestampedArchive(context.Background(), writeTestArchive(t, entries), bundleStore, timestampStore, timestamped.Timestamp().IssuedAt.Add(time.Minute)); !errors.Is(err, ErrArchiveInvalid) {
		t.Fatalf("expected noncanonical timestamp rejection, got %v", err)
	}
}

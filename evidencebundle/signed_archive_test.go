package evidencebundle

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSignedArchiveRoundTripIsDeterministicAndTrusted(t *testing.T) {
	bundle, signature, _, store := signedBundleFixture(t)
	verified, err := VerifySignature(
		context.Background(), bundle, signature, store, signature.SigningTime.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ExportSignedArchive(verified)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExportSignedArchive(verified)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("signed archive is not byte deterministic")
	}
	imported, err := ImportSignedArchive(
		context.Background(), first, store, signature.SigningTime.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Bundle().Manifest.BundleRoot != bundle.Manifest.BundleRoot ||
		imported.Signature() != signature {
		t.Fatal("signed archive round trip changed identity")
	}
}

func TestSignedArchiveRequiresEmbeddedSignature(t *testing.T) {
	bundle, signature, _, store := signedBundleFixture(t)
	unsigned, err := ExportArchive(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ImportSignedArchive(
		context.Background(), unsigned, store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, ErrBundleSignatureRequired) {
		t.Fatalf("expected missing signature rejection, got %v", err)
	}
}

func TestSignedArchiveRejectsModifiedSignatureAndObject(t *testing.T) {
	bundle, signature, _, store := signedBundleFixture(t)
	verified, err := VerifySignature(
		context.Background(), bundle, signature, store, signature.SigningTime.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ExportSignedArchive(verified)
	if err != nil {
		t.Fatal(err)
	}
	entries := readTestArchive(t, payload)
	var decoded Signature
	if err = json.Unmarshal(entries[SignatureEntryPath], &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.Value = decoded.Value[:len(decoded.Value)-4] + "AAAA"
	entries[SignatureEntryPath], err = CanonicalSignature(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ImportSignedArchive(
		context.Background(), writeTestArchive(t, entries), store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, ErrBundleSignatureInvalid) {
		t.Fatalf("expected modified signature rejection, got %v", err)
	}

	entries = readTestArchive(t, payload)
	for entryPath := range entries {
		if entryPath != ManifestEntryPath && entryPath != SignatureEntryPath {
			entries[entryPath][0] ^= 1
			break
		}
	}
	if _, err = ImportSignedArchive(
		context.Background(), writeTestArchive(t, entries), store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, ErrObjectDigestMismatch) {
		t.Fatalf("expected modified object rejection, got %v", err)
	}
}

func TestSignedArchiveRejectsUnexpectedAndNoncanonicalSignature(t *testing.T) {
	bundle, signature, _, store := signedBundleFixture(t)
	verified, err := VerifySignature(
		context.Background(), bundle, signature, store, signature.SigningTime.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ExportSignedArchive(verified)
	if err != nil {
		t.Fatal(err)
	}
	entries := readTestArchive(t, payload)
	entries["unexpected.json"] = []byte(`{}`)
	if _, err = ImportSignedArchive(
		context.Background(), writeTestArchive(t, entries), store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, ErrArchiveEntryMismatch) {
		t.Fatalf("expected unexpected entry rejection, got %v", err)
	}

	entries = readTestArchive(t, payload)
	entries[SignatureEntryPath] = append([]byte(" "), entries[SignatureEntryPath]...)
	if _, err = ImportSignedArchive(
		context.Background(), writeTestArchive(t, entries), store, signature.SigningTime.Add(time.Minute),
	); !errors.Is(err, ErrArchiveInvalid) {
		t.Fatalf("expected noncanonical signature rejection, got %v", err)
	}
}

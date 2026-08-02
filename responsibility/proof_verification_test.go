package responsibility

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/audit"
	"cargoos/evidencebundle"
	"cargoos/policy"
)

func TestPortableHandoverProofIsIndependentlyVerifiedEndToEnd(t *testing.T) {
	proof := portableHandoverProofFixture(t)
	report, err := VerifyPortableHandoverProof(
		context.Background(), proof.archive, proof.event, proof.entry, proof.certificate, proof.signed,
		proof.bundleTrust, proof.timestampTrust, proof.proofTrust, proof.verifiedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.ProofID != proof.signed.Binding.ProofID || report.BindingRoot != proof.signed.Binding.Root ||
		report.BundleID != proof.signed.Binding.BundleID || report.CertificateID != proof.certificate.CertificateID {
		t.Fatalf("incomplete portable handover verification: %#v", report)
	}
}

func TestPortableHandoverProofRejectsArchiveAndSourceSubstitution(t *testing.T) {
	proof := portableHandoverProofFixture(t)
	modifiedArchive := append([]byte(nil), proof.archive...)
	modifiedArchive[len(modifiedArchive)-1] ^= 1
	if _, err := VerifyPortableHandoverProof(
		context.Background(), modifiedArchive, proof.event, proof.entry, proof.certificate, proof.signed,
		proof.bundleTrust, proof.timestampTrust, proof.proofTrust, proof.verifiedAt,
	); err == nil {
		t.Fatal("expected modified portable archive rejection")
	}
	modifiedEvent := proof.event
	modifiedEvent.ObjectID = "substituted-object"
	if _, err := VerifyPortableHandoverProof(
		context.Background(), proof.archive, modifiedEvent, proof.entry, proof.certificate, proof.signed,
		proof.bundleTrust, proof.timestampTrust, proof.proofTrust, proof.verifiedAt,
	); !errors.Is(err, ErrHandoverProofBindingInvalid) {
		t.Fatalf("expected source event substitution rejection, got %v", err)
	}
}

type portableHandoverProofTestFixture struct {
	archive        []byte
	event          TransferredEvent
	entry          audit.Entry
	certificate    evidencebundle.VerificationCertificate
	signed         SignedHandoverProof
	bundleTrust    policy.TrustStore
	timestampTrust policy.TrustStore
	proofTrust     policy.TrustStore
	verifiedAt     time.Time
}

func portableHandoverProofFixture(t *testing.T) portableHandoverProofTestFixture {
	t.Helper()
	fixture := handoverProofFixture(t)
	bundleSigningTime := fixture.bundle.Manifest.GeneratedAt.Add(time.Minute)
	bundlePublic, bundlePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundleTrust, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "bundle-authority", KeyID: "bundle-key", Algorithm: policy.AlgorithmEd25519,
		PublicKey: bundlePublic, ValidFrom: bundleSigningTime.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	bundleSignature, err := evidencebundle.NewSignature(
		fixture.bundle, "bundle-authority", "bundle-key", bundleSigningTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := evidencebundle.SigningPayload(fixture.bundle, bundleSignature)
	if err != nil {
		t.Fatal(err)
	}
	bundleSignature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(bundlePrivate, payload))
	verifiedBundle, err := evidencebundle.VerifySignature(
		context.Background(), fixture.bundle, bundleSignature, bundleTrust, bundleSigningTime.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	timestampTime := bundleSigningTime.Add(time.Minute)
	timestampPublic, timestampPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	timestampTrust, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "timestamp-authority", KeyID: "timestamp-key", Algorithm: policy.AlgorithmEd25519,
		PublicKey: timestampPublic, ValidFrom: timestampTime.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	timestamp, err := evidencebundle.NewTrustedTimestamp(
		verifiedBundle, "timestamp-authority", "timestamp-key", "handover-ts-1", timestampTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = evidencebundle.TimestampSigningPayload(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	timestamp.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(timestampPrivate, payload))
	timestamped, err := evidencebundle.VerifyTrustedTimestamp(
		context.Background(), verifiedBundle, timestamp, timestampTrust, timestampTime.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := evidencebundle.ExportTimestampedArchive(timestamped)
	if err != nil {
		t.Fatal(err)
	}

	decisionReport, err := evidencebundle.VerifyDecision(context.Background(), fixture.bundle)
	if err != nil {
		t.Fatal(err)
	}
	certificateTime := timestampTime.Add(time.Minute)
	verifierPublic, verifierPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := evidencebundle.NewVerificationCertificate(
		decisionReport, timestamped, uuid.New(), "offline-verifier", "verifier-key", certificateTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = evidencebundle.VerificationCertificateSigningPayload(certificate)
	if err != nil {
		t.Fatal(err)
	}
	certificate.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(verifierPrivate, payload))
	binding, err := NewHandoverProofBinding(
		fixture.proofID, fixture.event, fixture.entry, fixture.bundle.Manifest, certificate,
	)
	if err != nil {
		t.Fatal(err)
	}
	outgoing, outgoingKey := signedHandoverProofRole(t, binding, HandoverSignerOutgoing, "vehicle-key")
	incoming, incomingKey := signedHandoverProofRole(t, binding, HandoverSignerIncoming, "warehouse-key")
	proofTrust, err := policy.NewMemoryTrustStore(
		policy.VerificationKey{
			SignerID: "offline-verifier", KeyID: "verifier-key", Algorithm: policy.AlgorithmEd25519,
			PublicKey: verifierPublic, ValidFrom: certificateTime.Add(-time.Minute),
		},
		outgoingKey, incomingKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return portableHandoverProofTestFixture{
		archive: archive, event: fixture.event, entry: fixture.entry, certificate: certificate,
		signed:      SignedHandoverProof{Binding: binding, Outgoing: outgoing, Incoming: incoming},
		bundleTrust: bundleTrust, timestampTrust: timestampTrust, proofTrust: proofTrust,
		verifiedAt: incoming.SignedAt.Add(time.Minute),
	}
}

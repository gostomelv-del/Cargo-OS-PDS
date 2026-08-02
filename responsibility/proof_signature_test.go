package responsibility

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

func TestHandoverProofRequiresValidSignaturesFromBothParticipants(t *testing.T) {
	fixture := handoverProofFixture(t)
	binding, err := NewHandoverProofBinding(
		fixture.proofID, fixture.event, fixture.entry, fixture.manifest, fixture.certificate,
	)
	if err != nil {
		t.Fatal(err)
	}
	outgoing, outgoingKey := signedHandoverProofRole(t, binding, HandoverSignerOutgoing, "vehicle-key")
	incoming, incomingKey := signedHandoverProofRole(t, binding, HandoverSignerIncoming, "warehouse-key")
	trustStore, err := policy.NewMemoryTrustStore(outgoingKey, incomingKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyHandoverProofSignatures(
		context.Background(), binding, outgoing, incoming, trustStore, incoming.SignedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Binding != binding || verified.Outgoing.Role != HandoverSignerOutgoing ||
		verified.Incoming.Role != HandoverSignerIncoming {
		t.Fatalf("incomplete signed handover proof: %#v", verified)
	}
}

func TestHandoverProofRejectsMissingSubstitutedAndRevokedParticipant(t *testing.T) {
	fixture := handoverProofFixture(t)
	binding, err := NewHandoverProofBinding(
		fixture.proofID, fixture.event, fixture.entry, fixture.manifest, fixture.certificate,
	)
	if err != nil {
		t.Fatal(err)
	}
	outgoing, outgoingKey := signedHandoverProofRole(t, binding, HandoverSignerOutgoing, "vehicle-key")
	incoming, incomingKey := signedHandoverProofRole(t, binding, HandoverSignerIncoming, "warehouse-key")
	trustStore, err := policy.NewMemoryTrustStore(outgoingKey, incomingKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyHandoverProofSignatures(
		context.Background(), binding, outgoing, HandoverProofSignature{}, trustStore, incoming.SignedAt.Add(time.Second),
	); !errors.Is(err, ErrHandoverSignerRole) {
		t.Fatalf("expected missing incoming signer rejection, got %v", err)
	}
	substituted := incoming
	substituted.Role = HandoverSignerOutgoing
	if _, err = VerifyHandoverProofSignatures(
		context.Background(), binding, outgoing, substituted, trustStore, incoming.SignedAt.Add(time.Second),
	); !errors.Is(err, ErrHandoverSignerIdentity) {
		t.Fatalf("expected role substitution rejection, got %v", err)
	}
	revokedAt := incoming.SignedAt.Add(time.Second)
	if err = trustStore.Revoke(incoming.SignerID, incoming.KeyID, revokedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyHandoverProofSignatures(
		context.Background(), binding, outgoing, incoming, trustStore, revokedAt.Add(time.Second),
	); !errors.Is(err, policy.ErrKeyRevoked) {
		t.Fatalf("expected revoked incoming signer rejection, got %v", err)
	}
}

func TestHandoverProofRejectsDelegatedSignerWithoutAuthorization(t *testing.T) {
	fixture := handoverProofFixture(t)
	binding, err := NewHandoverProofBinding(
		fixture.proofID, fixture.event, fixture.entry, fixture.manifest, fixture.certificate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewHandoverProofSignature(
		binding, HandoverSignerOutgoing, "unrelated-signer", "key", binding.CertificateIssuedAt,
	); !errors.Is(err, ErrHandoverSignerIdentity) {
		t.Fatalf("expected unauthorized delegated signer rejection, got %v", err)
	}
}

func signedHandoverProofRole(
	t *testing.T,
	binding HandoverProofBinding,
	role HandoverSignerRole,
	keyID string,
) (HandoverProofSignature, policy.VerificationKey) {
	t.Helper()
	participantID, err := handoverSignerParticipant(binding, role)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedAt := binding.CertificateIssuedAt.Add(time.Second)
	signature, err := NewHandoverProofSignature(binding, role, participantID.String(), keyID, signedAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := HandoverProofSigningPayload(signature)
	if err != nil {
		t.Fatal(err)
	}
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload[:]))
	return signature, policy.VerificationKey{
		SignerID: participantID.String(), KeyID: keyID, Algorithm: policy.AlgorithmEd25519,
		PublicKey: publicKey, ValidFrom: signedAt.Add(-time.Second),
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"cargoos/policy"
)

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("PDS_DATABASE_URL", "")
	if err := run(); !errors.Is(err, errDatabaseURLRequired) {
		t.Fatalf("expected database URL error, got %v", err)
	}
}

func TestDecodeAdmissionRequestIsStrictAndBounded(t *testing.T) {
	request := signedAdmissionRequest(t)
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAdmissionRequest(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Policy.Hash != request.Policy.Hash {
		t.Fatal("decoded policy identity changed")
	}

	payload[len(payload)-1] = ' '
	payload = append(payload, []byte(`,"unknown":true}`)...)
	if _, err = decodeAdmissionRequest(bytes.NewReader(payload)); !errors.Is(err, errInvalidAdmission) {
		t.Fatalf("unknown field was accepted: %v", err)
	}
	if _, err = decodeAdmissionRequest(strings.NewReader(`{} {}`)); !errors.Is(err, errInvalidAdmission) {
		t.Fatalf("trailing JSON was accepted: %v", err)
	}
	oversized := strings.NewReader(strings.Repeat(" ", maxAdmissionRequestBytes+1))
	if _, err = decodeAdmissionRequest(oversized); !errors.Is(err, errAdmissionTooLarge) {
		t.Fatalf("oversized input was accepted: %v", err)
	}
}

func TestAdmitPersistsOnlyVerifiedApprovedPolicy(t *testing.T) {
	request := signedAdmissionRequest(t)
	publicKey := testPublicKey(t, request)
	trustStore, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID:  request.Signature.SignerID,
		KeyID:     request.Signature.KeyID,
		Algorithm: policy.AlgorithmEd25519,
		PublicKey: publicKey,
		ValidFrom: request.Signature.SignedAt.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := policy.NewRegistry()
	activated, err := admit(context.Background(), request, trustStore, registry)
	if err != nil {
		t.Fatal(err)
	}
	if activated.VerifiedVersion().Version().Snapshot().Hash != request.Policy.Hash {
		t.Fatal("admitted policy identity changed")
	}
	resolved, err := registry.Resolve(context.Background(), request.Policy.PolicyID, request.ActivatedAt)
	if err != nil || resolved.Snapshot().Hash != request.Policy.Hash {
		t.Fatalf("admitted policy was not resolvable: %#v, %v", resolved, err)
	}

	tampered := request
	tampered.Signature.Value = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	rejectedRegistry := policy.NewRegistry()
	if _, err = admit(context.Background(), tampered, trustStore, rejectedRegistry); !errors.Is(err, policy.ErrInvalidSignature) {
		t.Fatalf("tampered signature was accepted: %v", err)
	}
	if _, err = rejectedRegistry.Resolve(context.Background(), request.Policy.PolicyID, request.ActivatedAt); !errors.Is(err, policy.ErrPolicyNotFound) {
		t.Fatalf("failed admission changed registry: %v", err)
	}
}

var generatedPrivateKey ed25519.PrivateKey

func signedAdmissionRequest(t *testing.T) admissionRequest {
	t.Helper()
	effective := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	version, err := policy.NewVersion(policy.Input{
		PolicyID:        "cargo-transfer",
		Version:         "1.0.0",
		SchemaVersion:   "policy.document.v1",
		EffectiveFrom:   effective,
		RequiredRuleIDs: []string{"weight"},
		Document: json.RawMessage(`{
			"evidence_qualification":{"version":"evidence.qualification.v1"},
			"rules":[{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","min_count":1}]
		}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	generatedPrivateKey = privateKey
	snapshot := version.Snapshot()
	signature := policy.Signature{
		SignerID:  "policy-authority",
		KeyID:     "key-1",
		Algorithm: policy.AlgorithmEd25519,
		SignedAt:  effective.Add(-2 * time.Minute),
	}
	payload, err := policy.SigningPayload(version, signature)
	if err != nil {
		t.Fatal(err)
	}
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return admissionRequest{
		Policy:    snapshot,
		Signature: signature,
		Approval: policy.ApprovalRecord{
			PolicyID:   snapshot.PolicyID,
			Version:    snapshot.Version,
			PolicyHash: snapshot.Hash,
			ApprovedBy: "policy-review-board",
			ApprovedAt: effective.Add(-time.Minute),
		},
		VerifiedAt:  effective.Add(-30 * time.Second),
		ActivatedAt: effective,
	}
}

func testPublicKey(t *testing.T, request admissionRequest) ed25519.PublicKey {
	t.Helper()
	if len(generatedPrivateKey) != ed25519.PrivateKeySize {
		t.Fatal("test private key was not generated")
	}
	publicKey := generatedPrivateKey.Public().(ed25519.PublicKey)
	version, err := policy.Rehydrate(request.Policy)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := policy.SigningPayload(version, request.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, mustDecodeSignature(t, request.Signature.Value)) {
		t.Fatal("test signature does not match generated key")
	}
	return publicKey
}

func mustDecodeSignature(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

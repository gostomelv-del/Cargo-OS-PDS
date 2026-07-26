package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

func TestDecodeTrustRequestIsStrictAndBounded(t *testing.T) {
	validFrom := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	payload := []byte(`{
		"action":"register",
		"signer_id":"policy-authority",
		"key_id":"key-1",
		"algorithm":"ED25519",
		"public_key":"` + base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)) + `",
		"valid_from":"` + validFrom.Format(time.RFC3339) + `"
	}`)
	request, err := decodeTrustRequest(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if request.Action != actionRegister || request.SignerID != "policy-authority" ||
		request.KeyID != "key-1" || len(request.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("unexpected request: %#v", request)
	}

	invalid := []string{
		`{"action":"register","signer_id":"authority","key_id":"key","algorithm":"RSA","public_key":"AA==","valid_from":"2026-07-26T10:00:00Z"}`,
		`{"action":"revoke","signer_id":"authority","key_id":"key","revoked_at":"2026-07-26T10:00:00Z","public_key":"AA=="}`,
		`{"action":"delete","signer_id":"authority","key_id":"key","revoked_at":"2026-07-26T10:00:00Z"}`,
		`{"action":"revoke","signer_id":"authority","key_id":"key","revoked_at":"2026-07-26T10:00:00Z","unknown":true}`,
		`{} {}`,
	}
	for _, body := range invalid {
		if _, err = decodeTrustRequest(strings.NewReader(body)); !errors.Is(err, errInvalidTrustRequest) {
			t.Fatalf("invalid request was accepted: %s, %v", body, err)
		}
	}
	oversized := strings.NewReader(strings.Repeat(" ", maxTrustRequestBytes+1))
	if _, err = decodeTrustRequest(oversized); !errors.Is(err, errTrustInputTooLarge) {
		t.Fatalf("oversized request was accepted: %v", err)
	}
}

func TestExecuteTrustRequestDispatchesExactOperation(t *testing.T) {
	validFrom := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	validUntil := validFrom.Add(24 * time.Hour)
	publicKey := bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	store := &recordingTrustStore{}
	register := trustRequest{
		Action: actionRegister, SignerID: "authority", KeyID: "key-1",
		Algorithm: policy.AlgorithmEd25519, PublicKey: publicKey,
		ValidFrom: validFrom, ValidUntil: &validUntil,
	}
	if err := executeTrustRequest(context.Background(), store, register); err != nil {
		t.Fatal(err)
	}
	publicKey[0] = 2
	if store.action != actionRegister ||
		store.key.SignerID != register.SignerID ||
		store.key.KeyID != register.KeyID ||
		store.key.PublicKey[0] != 1 ||
		store.key.ValidUntil == nil ||
		!store.key.ValidUntil.Equal(validUntil) {
		t.Fatalf("wrong registration dispatched: %#v", store)
	}

	revokedAt := validFrom.Add(time.Hour)
	revoke := trustRequest{
		Action: actionRevoke, SignerID: "authority", KeyID: "key-1", RevokedAt: revokedAt,
	}
	if err := executeTrustRequest(context.Background(), store, revoke); err != nil {
		t.Fatal(err)
	}
	if store.action != actionRevoke || !store.revokedAt.Equal(revokedAt) {
		t.Fatalf("wrong revocation dispatched: %#v", store)
	}
}

func TestExecuteTrustRequestPropagatesStoreFailure(t *testing.T) {
	target := errors.New("trust store rejected operation")
	store := &recordingTrustStore{err: target}
	err := executeTrustRequest(context.Background(), store, trustRequest{
		Action: actionRevoke, SignerID: "authority", KeyID: "key-1", RevokedAt: time.Now(),
	})
	if !errors.Is(err, target) {
		t.Fatalf("expected store error, got %v", err)
	}
}

type recordingTrustStore struct {
	action    trustAction
	key       policy.VerificationKey
	signerID  string
	keyID     string
	revokedAt time.Time
	err       error
}

func (s *recordingTrustStore) AddVerificationKey(_ context.Context, key policy.VerificationKey) error {
	s.action, s.key = actionRegister, key
	return s.err
}

func (s *recordingTrustStore) RevokeVerificationKey(
	_ context.Context,
	signerID string,
	keyID string,
	revokedAt time.Time,
) error {
	s.action, s.signerID, s.keyID, s.revokedAt = actionRevoke, signerID, keyID, revokedAt
	return s.err
}

func TestTrustRequestJSONUsesBase64PublicKey(t *testing.T) {
	request := trustRequest{
		Action: actionRegister, SignerID: "authority", KeyID: "key-1",
		Algorithm: policy.AlgorithmEd25519,
		PublicKey: bytes.Repeat([]byte{1}, ed25519.PublicKeySize),
		ValidFrom: time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(base64.StdEncoding.EncodeToString(request.PublicKey))) {
		t.Fatalf("public key was not encoded as base64: %s", payload)
	}
}

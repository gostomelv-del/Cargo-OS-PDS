package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const AlgorithmEd25519 = "ED25519"

var (
	ErrSignatureRequired     = errors.New("policy: signature is required")
	ErrSignerIDRequired      = errors.New("policy: signer ID is required")
	ErrKeyIDRequired         = errors.New("policy: key ID is required")
	ErrAlgorithmRequired     = errors.New("policy: signature algorithm is required")
	ErrSignedAtRequired      = errors.New("policy: signature time is required")
	ErrTrustStoreRequired    = errors.New("policy: trust store is required")
	ErrVerificationKeyAbsent = errors.New("policy: trusted verification key not found")
	ErrUnsupportedAlgorithm  = errors.New("policy: unsupported signature algorithm")
	ErrInvalidSignature      = errors.New("policy: invalid signature")
	ErrKeyNotYetValid        = errors.New("policy: verification key is not yet valid")
	ErrKeyExpired            = errors.New("policy: verification key is expired")
	ErrKeyRevoked            = errors.New("policy: verification key is revoked")
)

type Signature struct {
	SignerID  string    `json:"signer_id"`
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	SignedAt  time.Time `json:"signed_at"`
	Value     string    `json:"value"`
}

type VerificationKey struct {
	SignerID   string
	KeyID      string
	Algorithm  string
	PublicKey  []byte
	ValidFrom  time.Time
	ValidUntil *time.Time
	RevokedAt  *time.Time
}

type TrustStore interface {
	ResolveVerificationKey(context.Context, string, string) (VerificationKey, error)
}

type Verifier struct {
	trustStore TrustStore
}

type VerifiedVersion struct {
	version   *Version
	signature Signature
}

func NewVerifier(trustStore TrustStore) (*Verifier, error) {
	if trustStore == nil {
		return nil, ErrTrustStoreRequired
	}
	return &Verifier{trustStore: trustStore}, nil
}

func SigningPayload(version *Version, signature Signature) ([]byte, error) {
	if version == nil {
		return nil, ErrPolicyNotFound
	}
	envelope := struct {
		Domain     string    `json:"domain"`
		PolicyHash string    `json:"policy_hash"`
		SignerID   string    `json:"signer_id"`
		KeyID      string    `json:"key_id"`
		Algorithm  string    `json:"algorithm"`
		SignedAt   time.Time `json:"signed_at"`
	}{
		Domain: "cargoos:policy-signature:v1", PolicyHash: version.Snapshot().Hash,
		SignerID: strings.TrimSpace(signature.SignerID), KeyID: strings.TrimSpace(signature.KeyID),
		Algorithm: strings.TrimSpace(signature.Algorithm), SignedAt: signature.SignedAt.UTC(),
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return digest[:], nil
}

func (v *Verifier) Verify(ctx context.Context, version *Version, signature Signature) (*VerifiedVersion, error) {
	if v == nil || v.trustStore == nil {
		return nil, ErrTrustStoreRequired
	}
	if version == nil {
		return nil, ErrPolicyNotFound
	}
	signature.SignerID = strings.TrimSpace(signature.SignerID)
	signature.KeyID = strings.TrimSpace(signature.KeyID)
	signature.Algorithm = strings.TrimSpace(signature.Algorithm)
	signature.SignedAt = signature.SignedAt.UTC()
	switch {
	case signature.SignerID == "":
		return nil, ErrSignerIDRequired
	case signature.KeyID == "":
		return nil, ErrKeyIDRequired
	case signature.Algorithm == "":
		return nil, ErrAlgorithmRequired
	case signature.SignedAt.IsZero():
		return nil, ErrSignedAtRequired
	case signature.Value == "":
		return nil, ErrSignatureRequired
	}
	key, err := v.trustStore.ResolveVerificationKey(ctx, signature.SignerID, signature.KeyID)
	if err != nil {
		return nil, err
	}
	if key.SignerID != signature.SignerID || key.KeyID != signature.KeyID {
		return nil, ErrVerificationKeyAbsent
	}
	if key.Algorithm != signature.Algorithm || signature.Algorithm != AlgorithmEd25519 {
		return nil, ErrUnsupportedAlgorithm
	}
	if !key.ValidFrom.IsZero() && signature.SignedAt.Before(key.ValidFrom.UTC()) {
		return nil, ErrKeyNotYetValid
	}
	if key.ValidUntil != nil && !signature.SignedAt.Before(key.ValidUntil.UTC()) {
		return nil, ErrKeyExpired
	}
	if key.RevokedAt != nil && !signature.SignedAt.Before(key.RevokedAt.UTC()) {
		return nil, ErrKeyRevoked
	}
	value, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil || len(value) != ed25519.SignatureSize || len(key.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidSignature
	}
	payload, _ := SigningPayload(version, signature)
	if !ed25519.Verify(ed25519.PublicKey(key.PublicKey), payload, value) {
		return nil, ErrInvalidSignature
	}
	return &VerifiedVersion{version: version, signature: signature}, nil
}

func (v *VerifiedVersion) Version() *Version {
	if v == nil {
		return nil
	}
	return v.version
}

func (v *VerifiedVersion) Signature() Signature {
	if v == nil {
		return Signature{}
	}
	return v.signature
}

type MemoryTrustStore struct {
	mu   sync.RWMutex
	keys map[string]VerificationKey
}

func NewMemoryTrustStore(keys ...VerificationKey) (*MemoryTrustStore, error) {
	store := &MemoryTrustStore{keys: make(map[string]VerificationKey)}
	for _, key := range keys {
		if err := store.Add(key); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (s *MemoryTrustStore) Add(key VerificationKey) error {
	key.SignerID = strings.TrimSpace(key.SignerID)
	key.KeyID = strings.TrimSpace(key.KeyID)
	key.Algorithm = strings.TrimSpace(key.Algorithm)
	if key.SignerID == "" || key.KeyID == "" || key.Algorithm == "" || len(key.PublicKey) == 0 {
		return ErrVerificationKeyAbsent
	}
	key.PublicKey = append([]byte(nil), key.PublicKey...)
	s.mu.Lock()
	s.keys[key.SignerID+"\x00"+key.KeyID] = key
	s.mu.Unlock()
	return nil
}

func (s *MemoryTrustStore) ResolveVerificationKey(_ context.Context, signerID, keyID string) (VerificationKey, error) {
	if s == nil {
		return VerificationKey{}, ErrVerificationKeyAbsent
	}
	s.mu.RLock()
	key, found := s.keys[signerID+"\x00"+keyID]
	s.mu.RUnlock()
	if !found {
		return VerificationKey{}, ErrVerificationKeyAbsent
	}
	key.PublicKey = append([]byte(nil), key.PublicKey...)
	return key, nil
}

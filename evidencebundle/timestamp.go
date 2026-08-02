package evidencebundle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"cargoos/policy"
)

const (
	TimestampSchemaVersion = "cargoos.evidence-bundle.timestamp.v1"
	TimestampAlgorithm     = policy.AlgorithmEd25519
	timestampDomain        = "cargoos:evidence-bundle-timestamp:v1"
)

var (
	ErrBundleTimestampRequired = errors.New("evidencebundle: trusted timestamp is required")
	ErrTimestampAuthority      = errors.New("evidencebundle: timestamp authority identity is required")
	ErrBundleTimestampTime     = errors.New("evidencebundle: trusted timestamp time is invalid")
	ErrBundleTimestampBinding  = errors.New("evidencebundle: trusted timestamp binding is invalid")
	ErrBundleTimestampInvalid  = errors.New("evidencebundle: trusted timestamp signature is invalid")
)

// TrustedTimestamp is an externally signed assertion that the exact Evidence
// Bundle signature existed no later than IssuedAt. The timestamp authority's
// private key remains outside PDS.
type TrustedTimestamp struct {
	SchemaVersion      string    `json:"schema_version"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	HashAlgorithm      string    `json:"hash_algorithm"`
	AuthorityID        string    `json:"authority_id"`
	KeyID              string    `json:"key_id"`
	SerialNumber       string    `json:"serial_number"`
	IssuedAt           time.Time `json:"issued_at"`
	SignatureHash      string    `json:"signature_hash"`
	BundleRootHash     string    `json:"bundle_root_hash"`
	Value              string    `json:"value"`
}

type TimestampedBundle struct {
	verified  *VerifiedBundle
	timestamp TrustedTimestamp
}

func NewTrustedTimestamp(verified *VerifiedBundle, authorityID, keyID, serialNumber string, issuedAt time.Time) (TrustedTimestamp, error) {
	if verified == nil {
		return TrustedTimestamp{}, ErrBundleSignatureRequired
	}
	authorityID = strings.TrimSpace(authorityID)
	keyID = strings.TrimSpace(keyID)
	serialNumber = strings.TrimSpace(serialNumber)
	issuedAt = issuedAt.UTC()
	if authorityID == "" || keyID == "" || serialNumber == "" {
		return TrustedTimestamp{}, ErrTimestampAuthority
	}
	if issuedAt.IsZero() || issuedAt.Before(verified.signature.SigningTime.UTC()) {
		return TrustedTimestamp{}, ErrBundleTimestampTime
	}
	signaturePayload, err := CanonicalSignature(verified.signature)
	if err != nil {
		return TrustedTimestamp{}, err
	}
	return TrustedTimestamp{
		SchemaVersion: TimestampSchemaVersion, SignatureAlgorithm: TimestampAlgorithm,
		HashAlgorithm: HashAlgorithm, AuthorityID: authorityID, KeyID: keyID,
		SerialNumber: serialNumber, IssuedAt: issuedAt,
		SignatureHash: digest(signaturePayload), BundleRootHash: verified.bundle.Manifest.BundleRoot,
	}, nil
}

// TimestampSigningPayload returns the domain-separated SHA-256 digest for an
// external timestamp authority to sign.
func TimestampSigningPayload(timestamp TrustedTimestamp) ([]byte, error) {
	if err := validateTimestampBinding(timestamp, false); err != nil {
		return nil, err
	}
	envelope := struct {
		Domain             string    `json:"domain"`
		SchemaVersion      string    `json:"schema_version"`
		SignatureAlgorithm string    `json:"signature_algorithm"`
		HashAlgorithm      string    `json:"hash_algorithm"`
		AuthorityID        string    `json:"authority_id"`
		KeyID              string    `json:"key_id"`
		SerialNumber       string    `json:"serial_number"`
		IssuedAt           time.Time `json:"issued_at"`
		SignatureHash      string    `json:"signature_hash"`
		BundleRootHash     string    `json:"bundle_root_hash"`
	}{
		Domain: timestampDomain, SchemaVersion: timestamp.SchemaVersion,
		SignatureAlgorithm: timestamp.SignatureAlgorithm, HashAlgorithm: timestamp.HashAlgorithm,
		AuthorityID: timestamp.AuthorityID, KeyID: timestamp.KeyID, SerialNumber: timestamp.SerialNumber,
		IssuedAt: timestamp.IssuedAt.UTC(), SignatureHash: timestamp.SignatureHash,
		BundleRootHash: timestamp.BundleRootHash,
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	return hash[:], nil
}

func VerifyTrustedTimestamp(ctx context.Context, verified *VerifiedBundle, timestamp TrustedTimestamp, trustStore policy.TrustStore, verifiedAt time.Time) (*TimestampedBundle, error) {
	if verified == nil {
		return nil, ErrBundleSignatureRequired
	}
	if trustStore == nil {
		return nil, ErrBundleTrustStore
	}
	verifiedAt = verifiedAt.UTC()
	if verifiedAt.IsZero() || verifiedAt.Before(timestamp.IssuedAt.UTC()) || timestamp.IssuedAt.Before(verified.signature.SigningTime.UTC()) {
		return nil, ErrBundleTimestampTime
	}
	if err := validateTimestampBinding(timestamp, true); err != nil {
		return nil, err
	}
	signaturePayload, err := CanonicalSignature(verified.signature)
	if err != nil || timestamp.SignatureHash != digest(signaturePayload) || timestamp.BundleRootHash != verified.bundle.Manifest.BundleRoot {
		return nil, ErrBundleTimestampBinding
	}
	key, err := trustStore.ResolveVerificationKey(ctx, timestamp.AuthorityID, timestamp.KeyID)
	if err != nil {
		return nil, err
	}
	if key.SignerID != timestamp.AuthorityID || key.KeyID != timestamp.KeyID {
		return nil, policy.ErrVerificationKeyAbsent
	}
	if key.Algorithm != TimestampAlgorithm {
		return nil, policy.ErrUnsupportedAlgorithm
	}
	if !key.ValidFrom.IsZero() && timestamp.IssuedAt.Before(key.ValidFrom.UTC()) {
		return nil, policy.ErrKeyNotYetValid
	}
	if key.ValidUntil != nil && !timestamp.IssuedAt.Before(key.ValidUntil.UTC()) {
		return nil, policy.ErrKeyExpired
	}
	if key.RevokedAt != nil && !timestamp.IssuedAt.Before(key.RevokedAt.UTC()) {
		return nil, policy.ErrKeyRevoked
	}
	value, decodeErr := base64.StdEncoding.DecodeString(timestamp.Value)
	payload, payloadErr := TimestampSigningPayload(timestamp)
	if decodeErr != nil || payloadErr != nil || len(value) != ed25519.SignatureSize || len(key.PublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(key.PublicKey), payload, value) {
		return nil, ErrBundleTimestampInvalid
	}
	return &TimestampedBundle{verified: &VerifiedBundle{bundle: copyBundle(verified.bundle), signature: verified.signature}, timestamp: timestamp}, nil
}

func (timestamped *TimestampedBundle) VerifiedBundle() *VerifiedBundle {
	if timestamped == nil || timestamped.verified == nil {
		return nil
	}
	return &VerifiedBundle{bundle: copyBundle(timestamped.verified.bundle), signature: timestamped.verified.signature}
}

func (timestamped *TimestampedBundle) Timestamp() TrustedTimestamp {
	if timestamped == nil {
		return TrustedTimestamp{}
	}
	return timestamped.timestamp
}

func CanonicalTimestamp(timestamp TrustedTimestamp) ([]byte, error) {
	if err := validateTimestampBinding(timestamp, true); err != nil {
		return nil, err
	}
	return json.Marshal(timestamp)
}

func validateTimestampBinding(timestamp TrustedTimestamp, requireValue bool) error {
	if timestamp.SchemaVersion != TimestampSchemaVersion || timestamp.SignatureAlgorithm != TimestampAlgorithm || timestamp.HashAlgorithm != HashAlgorithm {
		return ErrBundleTimestampBinding
	}
	if timestamp.AuthorityID == "" || timestamp.KeyID == "" || timestamp.SerialNumber == "" ||
		timestamp.AuthorityID != strings.TrimSpace(timestamp.AuthorityID) || timestamp.KeyID != strings.TrimSpace(timestamp.KeyID) || timestamp.SerialNumber != strings.TrimSpace(timestamp.SerialNumber) {
		return ErrTimestampAuthority
	}
	if timestamp.IssuedAt.IsZero() {
		return ErrBundleTimestampTime
	}
	if timestamp.SignatureHash == "" || timestamp.BundleRootHash == "" {
		return ErrBundleTimestampBinding
	}
	if requireValue && timestamp.Value == "" {
		return ErrBundleTimestampRequired
	}
	return nil
}

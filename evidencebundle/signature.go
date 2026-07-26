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
	SignatureSchemaVersion = "cargoos.evidence-bundle.signature.v1"
	SignatureAlgorithm     = policy.AlgorithmEd25519
	signatureDomain        = "cargoos:evidence-bundle-signature:v1"
)

var (
	ErrBundleSignatureRequired = errors.New("evidencebundle: bundle signature is required")
	ErrBundleSignerRequired    = errors.New("evidencebundle: bundle signer identity is required")
	ErrBundleSigningTime       = errors.New("evidencebundle: bundle signing time is invalid")
	ErrBundleSignatureBinding  = errors.New("evidencebundle: bundle signature binding is invalid")
	ErrBundleSignatureInvalid  = errors.New("evidencebundle: bundle signature is invalid")
	ErrBundleTrustStore        = errors.New("evidencebundle: bundle trust store is required")
)

type Signature struct {
	SchemaVersion      string    `json:"schema_version"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	HashAlgorithm      string    `json:"hash_algorithm"`
	KeyID              string    `json:"key_id"`
	SignerID           string    `json:"signer_id"`
	SigningTime        time.Time `json:"signing_time"`
	SignedManifestHash string    `json:"signed_manifest_hash"`
	BundleRootHash     string    `json:"bundle_root_hash"`
	Value              string    `json:"value"`
}

type VerifiedBundle struct {
	bundle    Bundle
	signature Signature
}

// NewSignature prepares the immutable metadata that an external signer must
// sign. Private keys are not retained by the Evidence Bundle package.
func NewSignature(bundle Bundle, signerID, keyID string, signingTime time.Time) (Signature, error) {
	if err := Verify(bundle); err != nil {
		return Signature{}, err
	}
	signerID = strings.TrimSpace(signerID)
	keyID = strings.TrimSpace(keyID)
	signingTime = signingTime.UTC()
	if signerID == "" || keyID == "" {
		return Signature{}, ErrBundleSignerRequired
	}
	if signingTime.IsZero() || signingTime.Before(bundle.Manifest.GeneratedAt) {
		return Signature{}, ErrBundleSigningTime
	}
	manifestPayload, err := CanonicalManifest(bundle.Manifest)
	if err != nil {
		return Signature{}, err
	}
	return Signature{
		SchemaVersion:      SignatureSchemaVersion,
		SignatureAlgorithm: SignatureAlgorithm,
		HashAlgorithm:      HashAlgorithm,
		KeyID:              keyID,
		SignerID:           signerID,
		SigningTime:        signingTime,
		SignedManifestHash: digest(manifestPayload),
		BundleRootHash:     bundle.Manifest.BundleRoot,
	}, nil
}

// SigningPayload returns the domain-separated SHA-256 digest to be signed by
// an external Ed25519 signer.
func SigningPayload(bundle Bundle, signature Signature) ([]byte, error) {
	if err := validateSignatureBinding(bundle, signature, false); err != nil {
		return nil, err
	}
	envelope := struct {
		Domain             string    `json:"domain"`
		SchemaVersion      string    `json:"schema_version"`
		SignatureAlgorithm string    `json:"signature_algorithm"`
		HashAlgorithm      string    `json:"hash_algorithm"`
		KeyID              string    `json:"key_id"`
		SignerID           string    `json:"signer_id"`
		SigningTime        time.Time `json:"signing_time"`
		SignedManifestHash string    `json:"signed_manifest_hash"`
		BundleRootHash     string    `json:"bundle_root_hash"`
	}{
		Domain: signatureDomain, SchemaVersion: signature.SchemaVersion,
		SignatureAlgorithm: signature.SignatureAlgorithm, HashAlgorithm: signature.HashAlgorithm,
		KeyID: signature.KeyID, SignerID: signature.SignerID, SigningTime: signature.SigningTime.UTC(),
		SignedManifestHash: signature.SignedManifestHash, BundleRootHash: signature.BundleRootHash,
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	return hash[:], nil
}

// VerifySignature validates bundle integrity, signature binding, key trust,
// key lifecycle and the Ed25519 value at an explicit verification time.
func VerifySignature(
	ctx context.Context,
	bundle Bundle,
	signature Signature,
	trustStore policy.TrustStore,
	verifiedAt time.Time,
) (*VerifiedBundle, error) {
	if trustStore == nil {
		return nil, ErrBundleTrustStore
	}
	verifiedAt = verifiedAt.UTC()
	if verifiedAt.IsZero() || verifiedAt.Before(signature.SigningTime.UTC()) {
		return nil, ErrBundleSigningTime
	}
	if err := validateSignatureBinding(bundle, signature, true); err != nil {
		return nil, err
	}
	key, err := trustStore.ResolveVerificationKey(ctx, signature.SignerID, signature.KeyID)
	if err != nil {
		return nil, err
	}
	if key.SignerID != signature.SignerID || key.KeyID != signature.KeyID {
		return nil, policy.ErrVerificationKeyAbsent
	}
	if key.Algorithm != SignatureAlgorithm || signature.SignatureAlgorithm != SignatureAlgorithm {
		return nil, policy.ErrUnsupportedAlgorithm
	}
	if !key.ValidFrom.IsZero() && signature.SigningTime.Before(key.ValidFrom.UTC()) {
		return nil, policy.ErrKeyNotYetValid
	}
	if key.ValidUntil != nil && !signature.SigningTime.Before(key.ValidUntil.UTC()) {
		return nil, policy.ErrKeyExpired
	}
	if key.RevokedAt != nil && !signature.SigningTime.Before(key.RevokedAt.UTC()) {
		return nil, policy.ErrKeyRevoked
	}
	if key.ValidUntil != nil && !verifiedAt.Before(key.ValidUntil.UTC()) {
		return nil, policy.ErrKeyExpired
	}
	if key.RevokedAt != nil && !verifiedAt.Before(key.RevokedAt.UTC()) {
		return nil, policy.ErrKeyRevoked
	}
	value, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil || len(value) != ed25519.SignatureSize || len(key.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrBundleSignatureInvalid
	}
	payload, err := SigningPayload(bundle, signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key.PublicKey), payload, value) {
		return nil, ErrBundleSignatureInvalid
	}
	return &VerifiedBundle{bundle: copyBundle(bundle), signature: signature}, nil
}

func (verified *VerifiedBundle) Bundle() Bundle {
	if verified == nil {
		return Bundle{}
	}
	return copyBundle(verified.bundle)
}

func (verified *VerifiedBundle) Signature() Signature {
	if verified == nil {
		return Signature{}
	}
	return verified.signature
}

func CanonicalSignature(signature Signature) ([]byte, error) {
	if signature.SchemaVersion != SignatureSchemaVersion {
		return nil, ErrBundleSignatureBinding
	}
	return json.Marshal(signature)
}

func validateSignatureBinding(bundle Bundle, signature Signature, requireValue bool) error {
	if err := Verify(bundle); err != nil {
		return err
	}
	if signature.SchemaVersion != SignatureSchemaVersion ||
		signature.SignatureAlgorithm != SignatureAlgorithm ||
		signature.HashAlgorithm != HashAlgorithm {
		return ErrBundleSignatureBinding
	}
	if signature.SignerID == "" || signature.KeyID == "" ||
		signature.SignerID != strings.TrimSpace(signature.SignerID) ||
		signature.KeyID != strings.TrimSpace(signature.KeyID) {
		return ErrBundleSignerRequired
	}
	if signature.SigningTime.IsZero() || signature.SigningTime.Before(bundle.Manifest.GeneratedAt) {
		return ErrBundleSigningTime
	}
	manifestPayload, err := CanonicalManifest(bundle.Manifest)
	if err != nil {
		return err
	}
	if signature.SignedManifestHash != digest(manifestPayload) ||
		signature.BundleRootHash != bundle.Manifest.BundleRoot {
		return ErrBundleSignatureBinding
	}
	if requireValue && signature.Value == "" {
		return ErrBundleSignatureRequired
	}
	return nil
}

func copyBundle(bundle Bundle) Bundle {
	bundle.Manifest.Objects = append([]ObjectDescriptor(nil), bundle.Manifest.Objects...)
	bundle.Objects = copyObjects(bundle.Objects)
	return bundle
}

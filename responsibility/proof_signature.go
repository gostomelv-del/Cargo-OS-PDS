package responsibility

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"cargoos/policy"
)

const (
	HandoverProofSignatureSchema = "cargoos.handover-proof.signature.v1"
	handoverProofSignatureDomain = "cargoos:handover-proof-signature:v1"
)

var (
	ErrHandoverSignerRole     = errors.New("responsibility: handover signer role is invalid")
	ErrHandoverSignerIdentity = errors.New("responsibility: handover signer identity is invalid")
	ErrHandoverSignatureTime  = errors.New("responsibility: handover signature time is invalid")
	ErrHandoverSignatureValue = errors.New("responsibility: handover signature is invalid")
	ErrHandoverTrustStore     = errors.New("responsibility: handover trust store is required")
)

type HandoverSignerRole string

const (
	HandoverSignerOutgoing HandoverSignerRole = "OUTGOING_PARTICIPANT"
	HandoverSignerIncoming HandoverSignerRole = "INCOMING_PARTICIPANT"
)

type HandoverProofSignature struct {
	SchemaVersion string
	Role          HandoverSignerRole
	ParticipantID ParticipantID
	SignerID      string
	KeyID         string
	SignedAt      time.Time
	Algorithm     string
	BindingRoot   [32]byte
	Value         string
}

type SignedHandoverProof struct {
	Binding  HandoverProofBinding
	Outgoing HandoverProofSignature
	Incoming HandoverProofSignature
}

// NewHandoverProofSignature prepares one fixed-role signature. In this profile
// the trusted signer identity must equal the Participant identity; delegated
// signing requires a future explicit authorization registry.
func NewHandoverProofSignature(
	binding HandoverProofBinding,
	role HandoverSignerRole,
	signerID string,
	keyID string,
	signedAt time.Time,
) (HandoverProofSignature, error) {
	if err := binding.Validate(); err != nil {
		return HandoverProofSignature{}, err
	}
	participantID, err := handoverSignerParticipant(binding, role)
	if err != nil {
		return HandoverProofSignature{}, err
	}
	signerID = strings.TrimSpace(signerID)
	keyID = strings.TrimSpace(keyID)
	signedAt = signedAt.UTC().Truncate(time.Microsecond)
	if signerID == "" || signerID != participantID.String() || keyID == "" {
		return HandoverProofSignature{}, ErrHandoverSignerIdentity
	}
	if signedAt.IsZero() || signedAt.Before(binding.CertificateIssuedAt) {
		return HandoverProofSignature{}, ErrHandoverSignatureTime
	}
	return HandoverProofSignature{
		SchemaVersion: HandoverProofSignatureSchema, Role: role, ParticipantID: participantID,
		SignerID: signerID, KeyID: keyID, SignedAt: signedAt,
		Algorithm: policy.AlgorithmEd25519, BindingRoot: binding.Root,
	}, nil
}

// HandoverProofSigningPayload returns the fixed domain-separated digest for an
// external Ed25519 signer.
func HandoverProofSigningPayload(signature HandoverProofSignature) ([32]byte, error) {
	if err := validateHandoverProofSignature(signature, false); err != nil {
		return [32]byte{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(handoverProofSignatureDomain))
	writeRootString(digest, signature.SchemaVersion)
	writeRootString(digest, string(signature.Role))
	writeRootString(digest, signature.ParticipantID.String())
	writeRootString(digest, signature.SignerID)
	writeRootString(digest, signature.KeyID)
	writeProofScalar(digest, uint64(signature.SignedAt.UnixMicro()))
	writeRootString(digest, signature.Algorithm)
	_, _ = digest.Write(signature.BindingRoot[:])
	var root [32]byte
	digest.Sum(root[:0])
	return root, nil
}

// VerifyHandoverProofSignatures requires and verifies both participant roles.
// The two explicit checks avoid a dynamic signature collection and iteration.
func VerifyHandoverProofSignatures(
	ctx context.Context,
	binding HandoverProofBinding,
	outgoing HandoverProofSignature,
	incoming HandoverProofSignature,
	trustStore policy.TrustStore,
	verifiedAt time.Time,
) (SignedHandoverProof, error) {
	if trustStore == nil {
		return SignedHandoverProof{}, ErrHandoverTrustStore
	}
	if err := binding.Validate(); err != nil {
		return SignedHandoverProof{}, err
	}
	verifiedAt = verifiedAt.UTC()
	if verifiedAt.IsZero() || verifiedAt.Before(outgoing.SignedAt) || verifiedAt.Before(incoming.SignedAt) {
		return SignedHandoverProof{}, ErrHandoverSignatureTime
	}
	if err := verifyHandoverProofSignature(ctx, binding, HandoverSignerOutgoing, outgoing, trustStore, verifiedAt); err != nil {
		return SignedHandoverProof{}, err
	}
	if err := verifyHandoverProofSignature(ctx, binding, HandoverSignerIncoming, incoming, trustStore, verifiedAt); err != nil {
		return SignedHandoverProof{}, err
	}
	return SignedHandoverProof{Binding: binding, Outgoing: outgoing, Incoming: incoming}, nil
}

func verifyHandoverProofSignature(
	ctx context.Context,
	binding HandoverProofBinding,
	wantRole HandoverSignerRole,
	signature HandoverProofSignature,
	trustStore policy.TrustStore,
	verifiedAt time.Time,
) error {
	if err := validateHandoverProofSignature(signature, true); err != nil {
		return err
	}
	participantID, err := handoverSignerParticipant(binding, wantRole)
	if err != nil || signature.Role != wantRole || signature.ParticipantID != participantID ||
		signature.SignerID != participantID.String() || signature.BindingRoot != binding.Root ||
		signature.SignedAt.Before(binding.CertificateIssuedAt) {
		return ErrHandoverSignerIdentity
	}
	key, err := trustStore.ResolveVerificationKey(ctx, signature.SignerID, signature.KeyID)
	if err != nil {
		return err
	}
	if key.SignerID != signature.SignerID || key.KeyID != signature.KeyID {
		return policy.ErrVerificationKeyAbsent
	}
	if key.Algorithm != policy.AlgorithmEd25519 || signature.Algorithm != policy.AlgorithmEd25519 {
		return policy.ErrUnsupportedAlgorithm
	}
	if !key.ValidFrom.IsZero() && signature.SignedAt.Before(key.ValidFrom.UTC()) {
		return policy.ErrKeyNotYetValid
	}
	if key.ValidUntil != nil && (!signature.SignedAt.Before(key.ValidUntil.UTC()) || !verifiedAt.Before(key.ValidUntil.UTC())) {
		return policy.ErrKeyExpired
	}
	if key.RevokedAt != nil && (!signature.SignedAt.Before(key.RevokedAt.UTC()) || !verifiedAt.Before(key.RevokedAt.UTC())) {
		return policy.ErrKeyRevoked
	}
	value, decodeErr := base64.StdEncoding.DecodeString(signature.Value)
	payload, payloadErr := HandoverProofSigningPayload(signature)
	if decodeErr != nil || payloadErr != nil || len(value) != ed25519.SignatureSize ||
		len(key.PublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(key.PublicKey), payload[:], value) {
		return ErrHandoverSignatureValue
	}
	return nil
}

func validateHandoverProofSignature(signature HandoverProofSignature, requireValue bool) error {
	if signature.SchemaVersion != HandoverProofSignatureSchema ||
		(signature.Role != HandoverSignerOutgoing && signature.Role != HandoverSignerIncoming) {
		return ErrHandoverSignerRole
	}
	if validateParticipantID(signature.ParticipantID) != nil || signature.SignerID == "" ||
		signature.SignerID != strings.TrimSpace(signature.SignerID) || signature.SignerID != signature.ParticipantID.String() ||
		signature.KeyID == "" || signature.KeyID != strings.TrimSpace(signature.KeyID) {
		return ErrHandoverSignerIdentity
	}
	if signature.SignedAt.IsZero() || signature.SignedAt != signature.SignedAt.UTC().Truncate(time.Microsecond) {
		return ErrHandoverSignatureTime
	}
	if signature.Algorithm != policy.AlgorithmEd25519 || signature.BindingRoot == ([32]byte{}) {
		return ErrHandoverSignatureValue
	}
	if requireValue && signature.Value == "" {
		return ErrHandoverSignatureValue
	}
	return nil
}

func handoverSignerParticipant(binding HandoverProofBinding, role HandoverSignerRole) (ParticipantID, error) {
	switch role {
	case HandoverSignerOutgoing:
		return binding.FromParticipantID, nil
	case HandoverSignerIncoming:
		return binding.ToParticipantID, nil
	default:
		return "", ErrHandoverSignerRole
	}
}

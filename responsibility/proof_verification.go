package responsibility

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"cargoos/audit"
	"cargoos/evidencebundle"
	"cargoos/policy"
)

var ErrHandoverVerificationTime = errors.New("responsibility: handover verification time is invalid")

// PortableHandoverProof contains every artifact required to verify a physical
// Responsibility Transfer without consulting mutable runtime state.
type PortableHandoverProof struct {
	ProofID           uuid.UUID
	Transfer          TransferredEvent
	AuditEntry        audit.Entry
	Bundle            evidencebundle.Bundle
	BundleSignature   evidencebundle.Signature
	Timestamp         evidencebundle.TrustedTimestamp
	Certificate       evidencebundle.VerificationCertificate
	OutgoingSignature HandoverProofSignature
	IncomingSignature HandoverProofSignature
}

// VerifiedPortableHandoverProof is returned only after every cryptographic,
// decision, audit-lineage, Responsibility, and Participant binding succeeds.
type VerifiedPortableHandoverProof struct {
	Proof       SignedHandoverProof
	Certificate evidencebundle.VerificationCertificate
}

// VerifyPortableHandoverProof independently verifies the complete artifact in
// canonical dependency order. It deliberately re-verifies every layer instead
// of accepting a cached verification result.
func VerifyPortableHandoverProof(
	ctx context.Context,
	portable PortableHandoverProof,
	trustStore policy.TrustStore,
	verifiedAt time.Time,
) (VerifiedPortableHandoverProof, error) {
	if trustStore == nil {
		return VerifiedPortableHandoverProof{}, ErrHandoverTrustStore
	}
	verifiedAt = verifiedAt.UTC()
	if verifiedAt.IsZero() {
		return VerifiedPortableHandoverProof{}, ErrHandoverVerificationTime
	}

	verifiedBundle, err := evidencebundle.VerifySignature(
		ctx, portable.Bundle, portable.BundleSignature, trustStore, verifiedAt,
	)
	if err != nil {
		return VerifiedPortableHandoverProof{}, err
	}
	timestamped, err := evidencebundle.VerifyTrustedTimestamp(
		ctx, verifiedBundle, portable.Timestamp, trustStore, verifiedAt,
	)
	if err != nil {
		return VerifiedPortableHandoverProof{}, err
	}
	certificate, err := evidencebundle.VerifyVerificationCertificate(
		ctx, timestamped, portable.Certificate, trustStore, verifiedAt,
	)
	if err != nil {
		return VerifiedPortableHandoverProof{}, err
	}
	binding, err := NewHandoverProofBinding(
		portable.ProofID,
		portable.Transfer,
		portable.AuditEntry,
		portable.Bundle.Manifest,
		certificate,
	)
	if err != nil {
		return VerifiedPortableHandoverProof{}, err
	}
	signed, err := VerifyHandoverProofSignatures(
		ctx,
		binding,
		portable.OutgoingSignature,
		portable.IncomingSignature,
		trustStore,
		verifiedAt,
	)
	if err != nil {
		return VerifiedPortableHandoverProof{}, err
	}
	return VerifiedPortableHandoverProof{Proof: signed, Certificate: certificate}, nil
}

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

var ErrPortableHandoverProofInvalid = errors.New("responsibility: portable handover proof is invalid")

type PortableHandoverVerification struct {
	ProofID       uuid.UUID
	BindingRoot   [32]byte
	BundleID      uuid.UUID
	EvaluationID  uuid.UUID
	CertificateID uuid.UUID
	VerifiedAt    time.Time
}

// VerifyPortableHandoverProof independently imports and verifies the portable
// Evidence Bundle, repeats decision/certificate verification, reconstructs the
// handover binding from source artifacts, and finally verifies both Participant
// signatures. No precomputed binding field is trusted.
func VerifyPortableHandoverProof(
	ctx context.Context,
	archive []byte,
	event TransferredEvent,
	entry audit.Entry,
	certificate evidencebundle.VerificationCertificate,
	signed SignedHandoverProof,
	bundleTrustStore policy.TrustStore,
	timestampTrustStore policy.TrustStore,
	proofTrustStore policy.TrustStore,
	verifiedAt time.Time,
) (PortableHandoverVerification, error) {
	verifiedAt = verifiedAt.UTC()
	if verifiedAt.IsZero() || proofTrustStore == nil {
		return PortableHandoverVerification{}, ErrPortableHandoverProofInvalid
	}
	timestamped, err := evidencebundle.ImportTimestampedArchive(
		ctx, archive, bundleTrustStore, timestampTrustStore, verifiedAt,
	)
	if err != nil {
		return PortableHandoverVerification{}, err
	}
	verifiedCertificate, err := evidencebundle.VerifyVerificationCertificate(
		ctx, timestamped, certificate, proofTrustStore, verifiedAt,
	)
	if err != nil {
		return PortableHandoverVerification{}, err
	}
	reference, err := timestamped.AuditReference()
	if err != nil {
		return PortableHandoverVerification{}, err
	}
	expected, err := NewHandoverProofBindingFromReference(
		signed.Binding.ProofID, event, entry, reference, verifiedCertificate,
	)
	if err != nil || expected != signed.Binding {
		return PortableHandoverVerification{}, ErrPortableHandoverProofInvalid
	}
	verified, err := VerifyHandoverProofSignatures(
		ctx, expected, signed.Outgoing, signed.Incoming, proofTrustStore, verifiedAt,
	)
	if err != nil {
		return PortableHandoverVerification{}, err
	}
	return PortableHandoverVerification{
		ProofID: verified.Binding.ProofID, BindingRoot: verified.Binding.Root,
		BundleID: verified.Binding.BundleID, EvaluationID: verified.Binding.EvaluationID,
		CertificateID: verified.Binding.CertificateID, VerifiedAt: verifiedAt,
	}, nil
}

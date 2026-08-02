package responsibility

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"time"

	"github.com/google/uuid"

	"cargoos/audit"
	"cargoos/evidencebundle"
)

const handoverProofBindingDomain = "cargoos:handover-proof-binding:v1"

var ErrHandoverProofBindingInvalid = errors.New("responsibility: handover proof binding is invalid")

// HandoverProofBinding is the fixed-value core of a portable Proof of
// Handover. It binds existing verified artifacts without copying the Evidence
// Bundle or recalculating its Evidence Objects.
type HandoverProofBinding struct {
	ProofID             uuid.UUID
	ObjectID            PhysicalObjectID
	FromParticipantID   ParticipantID
	ToParticipantID     ParticipantID
	TransferVersion     uint64
	TransferredAt       time.Time
	TransferRoot        [32]byte
	AuditSequence       uint64
	AuditPreviousRoot   [32]byte
	AuditRoot           [32]byte
	BundleID            uuid.UUID
	EvaluationID        uuid.UUID
	SessionID           uuid.UUID
	BundleRoot          [32]byte
	PolicyHash          string
	CertificateID       uuid.UUID
	CertificateRoot     [32]byte
	CertificateIssuedAt time.Time
	Root                [32]byte
}

func NewHandoverProofBinding(
	proofID uuid.UUID,
	event TransferredEvent,
	entry audit.Entry,
	manifest evidencebundle.Manifest,
	certificate evidencebundle.VerificationCertificate,
) (HandoverProofBinding, error) {
	transferRoot, err := TransferredEventRoot(event)
	if err != nil || proofID == uuid.Nil || entry.Validate() != nil ||
		entry.Kind != audit.RecordResponsibilityHandover || entry.RecordRoot != transferRoot ||
		!entry.OccurredAt.Equal(event.TransferredAt.UTC().Truncate(time.Microsecond)) {
		return HandoverProofBinding{}, ErrHandoverProofBindingInvalid
	}
	bundleRecord, err := evidencebundle.NewAuditRecord(manifest)
	if err != nil || certificate.CertificateID == uuid.Nil || certificate.BundleID != manifest.BundleID ||
		certificate.EvaluationID != manifest.EvaluationID || certificate.BundleRoot != manifest.BundleRoot ||
		certificate.Policy != manifest.Policy || certificate.IssuedAt.IsZero() ||
		certificate.IssuedAt.Before(event.TransferredAt) {
		return HandoverProofBinding{}, ErrHandoverProofBindingInvalid
	}
	certificatePayload, err := evidencebundle.CanonicalVerificationCertificate(certificate)
	if err != nil {
		return HandoverProofBinding{}, ErrHandoverProofBindingInvalid
	}
	binding := HandoverProofBinding{
		ProofID: proofID, ObjectID: event.ObjectID,
		FromParticipantID: event.FromParticipantID, ToParticipantID: event.ToParticipantID,
		TransferVersion: event.Version, TransferredAt: event.TransferredAt.UTC().Truncate(time.Microsecond),
		TransferRoot: transferRoot, AuditSequence: entry.Sequence,
		AuditPreviousRoot: entry.PreviousRoot, AuditRoot: entry.Root,
		BundleID: manifest.BundleID, EvaluationID: manifest.EvaluationID, SessionID: manifest.SessionID,
		BundleRoot: bundleRecord.BundleRoot, PolicyHash: manifest.Policy.Hash,
		CertificateID: certificate.CertificateID, CertificateRoot: sha256.Sum256(certificatePayload),
		CertificateIssuedAt: certificate.IssuedAt.UTC().Truncate(time.Microsecond),
	}
	binding.Root = calculateHandoverProofBindingRoot(binding)
	return binding, nil
}

func (binding HandoverProofBinding) Validate() error {
	if binding.ProofID == uuid.Nil || validateObjectID(binding.ObjectID) != nil ||
		validateParticipantID(binding.FromParticipantID) != nil || validateParticipantID(binding.ToParticipantID) != nil ||
		binding.FromParticipantID == binding.ToParticipantID || binding.TransferVersion < 2 ||
		binding.TransferredAt.IsZero() || binding.TransferredAt != binding.TransferredAt.UTC().Truncate(time.Microsecond) ||
		binding.TransferRoot == ([32]byte{}) || binding.AuditSequence == 0 || binding.AuditRoot == ([32]byte{}) ||
		binding.BundleID == uuid.Nil || binding.EvaluationID == uuid.Nil || binding.SessionID == uuid.Nil ||
		binding.BundleRoot == ([32]byte{}) || binding.PolicyHash == "" || binding.CertificateID == uuid.Nil ||
		binding.CertificateRoot == ([32]byte{}) || binding.CertificateIssuedAt.IsZero() ||
		binding.CertificateIssuedAt != binding.CertificateIssuedAt.UTC().Truncate(time.Microsecond) ||
		binding.CertificateIssuedAt.Before(binding.TransferredAt) || binding.Root == ([32]byte{}) ||
		binding.Root != calculateHandoverProofBindingRoot(binding) {
		return ErrHandoverProofBindingInvalid
	}
	return nil
}

func calculateHandoverProofBindingRoot(binding HandoverProofBinding) [32]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(handoverProofBindingDomain))
	writeProofUUID(digest, binding.ProofID)
	writeRootString(digest, binding.ObjectID.String())
	writeRootString(digest, binding.FromParticipantID.String())
	writeRootString(digest, binding.ToParticipantID.String())
	writeProofScalar(digest, binding.TransferVersion)
	writeProofScalar(digest, uint64(binding.TransferredAt.UnixMicro()))
	_, _ = digest.Write(binding.TransferRoot[:])
	writeProofScalar(digest, binding.AuditSequence)
	_, _ = digest.Write(binding.AuditPreviousRoot[:])
	_, _ = digest.Write(binding.AuditRoot[:])
	writeProofUUID(digest, binding.BundleID)
	writeProofUUID(digest, binding.EvaluationID)
	writeProofUUID(digest, binding.SessionID)
	_, _ = digest.Write(binding.BundleRoot[:])
	writeRootString(digest, binding.PolicyHash)
	writeProofUUID(digest, binding.CertificateID)
	_, _ = digest.Write(binding.CertificateRoot[:])
	writeProofScalar(digest, uint64(binding.CertificateIssuedAt.UnixMicro()))
	var root [32]byte
	digest.Sum(root[:0])
	return root
}

func writeProofUUID(digest hash.Hash, value uuid.UUID) {
	_, _ = digest.Write(value[:])
}

func writeProofScalar(digest hash.Hash, value uint64) {
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], value)
	_, _ = digest.Write(scalar[:])
}

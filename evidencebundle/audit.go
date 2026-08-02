package evidencebundle

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrAuditRecordInvalid  = errors.New("evidencebundle: audit record is invalid")
	ErrAuditRecordNotFound = errors.New("evidencebundle: audit record not found")
	ErrAuditRecordExists   = errors.New("evidencebundle: audit record already exists")
)

type AuditRecord struct {
	BundleID     uuid.UUID
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	GeneratedAt  time.Time
	BundleRoot   [32]byte
}

type BundleAuditReference struct {
	Record     AuditRecord
	Policy     PolicyReference
	BundleRoot string
}

func (reference BundleAuditReference) Validate() error {
	root, err := decodeBundleRoot(reference.BundleRoot)
	if err != nil || reference.Record.Validate() != nil || root != reference.Record.BundleRoot ||
		reference.Policy.PolicyID == "" || reference.Policy.Version == "" ||
		!sha256Pattern.MatchString(reference.Policy.Hash) {
		return ErrAuditRecordInvalid
	}
	return nil
}

func NewAuditRecord(manifest Manifest) (AuditRecord, error) {
	if manifest.BundleID == uuid.Nil || manifest.EvaluationID == uuid.Nil ||
		manifest.SessionID == uuid.Nil || manifest.GeneratedAt.IsZero() ||
		manifest.SchemaVersion != SchemaVersion || manifest.HashAlgorithm != HashAlgorithm ||
		calculateRoot(manifest) != manifest.BundleRoot {
		return AuditRecord{}, ErrAuditRecordInvalid
	}
	root, err := decodeBundleRoot(manifest.BundleRoot)
	if err != nil {
		return AuditRecord{}, ErrAuditRecordInvalid
	}
	return AuditRecord{
		BundleID: manifest.BundleID, EvaluationID: manifest.EvaluationID,
		SessionID:   manifest.SessionID,
		GeneratedAt: manifest.GeneratedAt.UTC().Truncate(time.Microsecond),
		BundleRoot:  root,
	}, nil
}

func (record AuditRecord) Validate() error {
	if record.BundleID == uuid.Nil || record.EvaluationID == uuid.Nil ||
		record.SessionID == uuid.Nil || record.GeneratedAt.IsZero() ||
		record.GeneratedAt != record.GeneratedAt.UTC().Truncate(time.Microsecond) ||
		record.BundleRoot == ([32]byte{}) {
		return ErrAuditRecordInvalid
	}
	return nil
}

// AuditReference returns the fixed-value identity of an already verified
// timestamped Bundle without copying its objects or exposing internal slices.
func (timestamped *TimestampedBundle) AuditReference() (BundleAuditReference, error) {
	if timestamped == nil || timestamped.verified == nil {
		return BundleAuditReference{}, ErrAuditRecordInvalid
	}
	manifest := timestamped.verified.bundle.Manifest
	record, err := NewAuditRecord(manifest)
	if err != nil {
		return BundleAuditReference{}, err
	}
	return BundleAuditReference{Record: record, Policy: manifest.Policy, BundleRoot: manifest.BundleRoot}, nil
}

func decodeBundleRoot(value string) ([32]byte, error) {
	var root [32]byte
	if len(value) != len("sha256:")+hex.EncodedLen(len(root)) {
		return [32]byte{}, ErrAuditRecordInvalid
	}
	decoded, err := hex.Decode(root[:], []byte(value[len("sha256:"):]))
	if err != nil || decoded != len(root) || root == ([32]byte{}) {
		return [32]byte{}, ErrAuditRecordInvalid
	}
	return root, nil
}

type AuditRepository interface {
	SaveEvidenceBundleAudit(context.Context, AuditRecord) error
	FindEvidenceBundleAudit(context.Context, uuid.UUID) (AuditRecord, error)
}

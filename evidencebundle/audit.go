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

func NewAuditRecord(manifest Manifest) (AuditRecord, error) {
	if manifest.BundleID == uuid.Nil || manifest.EvaluationID == uuid.Nil ||
		manifest.SessionID == uuid.Nil || manifest.GeneratedAt.IsZero() ||
		manifest.SchemaVersion != SchemaVersion || manifest.HashAlgorithm != HashAlgorithm ||
		calculateRoot(manifest) != manifest.BundleRoot {
		return AuditRecord{}, ErrAuditRecordInvalid
	}
	var root [32]byte
	if len(manifest.BundleRoot) != len("sha256:")+hex.EncodedLen(len(root)) {
		return AuditRecord{}, ErrAuditRecordInvalid
	}
	decoded, err := hex.Decode(root[:], []byte(manifest.BundleRoot[len("sha256:"):]))
	if err != nil || decoded != len(root) || root == ([32]byte{}) {
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

type AuditRepository interface {
	SaveEvidenceBundleAudit(context.Context, AuditRecord) error
	FindEvidenceBundleAudit(context.Context, uuid.UUID) (AuditRecord, error)
}

package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEvidenceIDRequired     = errors.New("evidence: evidence ID is required")
	ErrSessionIDRequired      = errors.New("evidence: session ID is required")
	ErrSourceIDRequired       = errors.New("evidence: source ID is required")
	ErrSourceTypeRequired     = errors.New("evidence: source type is required")
	ErrInvalidEvidenceType    = errors.New("evidence: invalid evidence type")
	ErrObservedAtRequired     = errors.New("evidence: observed timestamp is required")
	ErrReceivedAtRequired     = errors.New("evidence: received timestamp is required")
	ErrInvalidTimestampOrder  = errors.New("evidence: received timestamp precedes observation")
	ErrInvalidPayload         = errors.New("evidence: payload must be one valid JSON value")
	ErrInvalidConfidence      = errors.New("evidence: confidence must be between zero and one")
	ErrSchemaVersionRequired  = errors.New("evidence: schema version is required")
	ErrRuntimeVersionRequired = errors.New("evidence: runtime version is required")
	ErrAcquisitionRequired    = errors.New("evidence: acquisition method is required")
	ErrIntegrityMismatch      = errors.New("evidence: payload integrity mismatch")
	ErrNonCanonicalPayload    = errors.New("evidence: payload is not canonical JSON")
)

type Type string

const (
	TypeContact             Type = "CONTACT"
	TypePosition            Type = "POSITION"
	TypeForce               Type = "FORCE"
	TypeWeight              Type = "WEIGHT"
	TypeImage               Type = "IMAGE"
	TypeVideo               Type = "VIDEO"
	TypeRFID                Type = "RFID"
	TypeBarcode             Type = "BARCODE"
	TypeLocalization        Type = "LOCALIZATION"
	TypeEnvironment         Type = "ENVIRONMENT"
	TypeSecurity            Type = "SECURITY"
	TypeSystemEvent         Type = "SYSTEM_EVENT"
	TypeHumanConfirmation   Type = "HUMAN_CONFIRMATION"
	TypeHardwareAttestation Type = "HARDWARE_ATTESTATION"
)

var typePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

type IntegrityMetadata struct {
	Algorithm         string `json:"algorithm"`
	PayloadDigest     string `json:"payload_digest"`
	SchemaVersion     string `json:"schema_version"`
	RuntimeVersion    string `json:"runtime_version"`
	AcquisitionMethod string `json:"acquisition_method"`
}

type Snapshot struct {
	EvidenceID   uuid.UUID         `json:"evidence_id"`
	SessionID    uuid.UUID         `json:"session_id"`
	SourceID     string            `json:"source_id"`
	SourceType   string            `json:"source_type"`
	EvidenceType Type              `json:"evidence_type"`
	ObservedAt   time.Time         `json:"observed_at"`
	ReceivedAt   time.Time         `json:"received_at"`
	Payload      json.RawMessage   `json:"payload"`
	Confidence   *float64          `json:"confidence,omitempty"`
	Provenance   map[string]string `json:"provenance,omitempty"`
	Integrity    IntegrityMetadata `json:"integrity"`
}

type Input struct {
	EvidenceID        uuid.UUID
	SessionID         uuid.UUID
	SourceID          string
	SourceType        string
	EvidenceType      Type
	ObservedAt        time.Time
	ReceivedAt        time.Time
	Payload           json.RawMessage
	Confidence        *float64
	Provenance        map[string]string
	SchemaVersion     string
	RuntimeVersion    string
	AcquisitionMethod string
}

// Object is immutable after construction. Snapshot returns defensive copies of
// every reference-backed field.
type Object struct {
	snapshot Snapshot
}

func NewObject(input Input) (*Object, error) {
	payload, err := canonicalJSON(input.Payload)
	if err != nil {
		return nil, err
	}
	input.SourceID = strings.TrimSpace(input.SourceID)
	input.SourceType = strings.TrimSpace(input.SourceType)
	input.SchemaVersion = strings.TrimSpace(input.SchemaVersion)
	input.RuntimeVersion = strings.TrimSpace(input.RuntimeVersion)
	input.AcquisitionMethod = strings.TrimSpace(input.AcquisitionMethod)
	snapshot := Snapshot{
		EvidenceID:   input.EvidenceID,
		SessionID:    input.SessionID,
		SourceID:     input.SourceID,
		SourceType:   input.SourceType,
		EvidenceType: input.EvidenceType,
		ObservedAt:   input.ObservedAt.UTC(),
		ReceivedAt:   input.ReceivedAt.UTC(),
		Payload:      payload,
		Confidence:   copyConfidence(input.Confidence),
		Provenance:   copyProvenance(input.Provenance),
		Integrity: IntegrityMetadata{
			Algorithm:         "SHA-256",
			PayloadDigest:     digest(payload),
			SchemaVersion:     input.SchemaVersion,
			RuntimeVersion:    input.RuntimeVersion,
			AcquisitionMethod: input.AcquisitionMethod,
		},
	}
	if err = validateSnapshot(snapshot); err != nil {
		return nil, err
	}
	return &Object{snapshot: snapshot}, nil
}

func Rehydrate(snapshot Snapshot) (*Object, error) {
	if err := VerifySnapshot(snapshot); err != nil {
		return nil, err
	}
	return &Object{snapshot: copySnapshot(snapshot)}, nil
}

func (o *Object) Snapshot() Snapshot {
	if o == nil {
		return Snapshot{}
	}
	return copySnapshot(o.snapshot)
}

func (o *Object) VerifyIntegrity() error {
	if o == nil {
		return ErrEvidenceIDRequired
	}
	return VerifySnapshot(o.snapshot)
}

func VerifySnapshot(snapshot Snapshot) error {
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	canonical, err := canonicalJSON(snapshot.Payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, snapshot.Payload) {
		return ErrNonCanonicalPayload
	}
	if snapshot.Integrity.Algorithm != "SHA-256" || snapshot.Integrity.PayloadDigest != digest(snapshot.Payload) {
		return ErrIntegrityMismatch
	}
	return nil
}

func validateSnapshot(snapshot Snapshot) error {
	switch {
	case snapshot.EvidenceID == uuid.Nil:
		return ErrEvidenceIDRequired
	case snapshot.SessionID == uuid.Nil:
		return ErrSessionIDRequired
	case strings.TrimSpace(snapshot.SourceID) == "":
		return ErrSourceIDRequired
	case strings.TrimSpace(snapshot.SourceType) == "":
		return ErrSourceTypeRequired
	case !typePattern.MatchString(string(snapshot.EvidenceType)):
		return ErrInvalidEvidenceType
	case snapshot.ObservedAt.IsZero():
		return ErrObservedAtRequired
	case snapshot.ReceivedAt.IsZero():
		return ErrReceivedAtRequired
	case snapshot.ReceivedAt.Before(snapshot.ObservedAt):
		return ErrInvalidTimestampOrder
	case snapshot.Confidence != nil && (*snapshot.Confidence < 0 || *snapshot.Confidence > 1):
		return ErrInvalidConfidence
	case strings.TrimSpace(snapshot.Integrity.SchemaVersion) == "":
		return ErrSchemaVersionRequired
	case strings.TrimSpace(snapshot.Integrity.RuntimeVersion) == "":
		return ErrRuntimeVersionRequired
	case strings.TrimSpace(snapshot.Integrity.AcquisitionMethod) == "":
		return ErrAcquisitionRequired
	}
	return nil
}

func canonicalJSON(payload []byte) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrInvalidPayload
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidPayload
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	return canonical, nil
}

func digest(payload []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

func copySnapshot(snapshot Snapshot) Snapshot {
	snapshot.Payload = append(json.RawMessage(nil), snapshot.Payload...)
	snapshot.Confidence = copyConfidence(snapshot.Confidence)
	snapshot.Provenance = copyProvenance(snapshot.Provenance)
	return snapshot
}

func copyConfidence(confidence *float64) *float64 {
	if confidence == nil {
		return nil
	}
	copy := *confidence
	return &copy
}

func copyProvenance(provenance map[string]string) map[string]string {
	if len(provenance) == 0 {
		return nil
	}
	copy := make(map[string]string, len(provenance))
	for key, value := range provenance {
		copy[key] = value
	}
	return copy
}

package evidence

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrQualificationPolicyVersionRequired = errors.New("evidence: qualification policy version is required")
	ErrInvalidQualificationMaxAge         = errors.New("evidence: qualification max age must not be negative")
	ErrInvalidQualificationTolerance      = errors.New("evidence: qualification future tolerance must not be negative")
	ErrInvalidQualificationConfidence     = errors.New("evidence: qualification minimum confidence must be between zero and one")
	ErrQualificationTimeRequired          = errors.New("evidence: qualification time is required")
)

type QualificationStatus string

const (
	QualificationQualified   QualificationStatus = "QUALIFIED"
	QualificationRejected    QualificationStatus = "REJECTED"
	QualificationUnavailable QualificationStatus = "UNAVAILABLE"
)

type QualificationReasonCode string

const (
	ReasonEvidenceUnavailable QualificationReasonCode = "EVIDENCE_UNAVAILABLE"
	ReasonIntegrityInvalid    QualificationReasonCode = "INTEGRITY_INVALID"
	ReasonSourceUntrusted     QualificationReasonCode = "SOURCE_UNTRUSTED"
	ReasonTypeNotAllowed      QualificationReasonCode = "TYPE_NOT_ALLOWED"
	ReasonTimestampFuture     QualificationReasonCode = "TIMESTAMP_FUTURE"
	ReasonEvidenceExpired     QualificationReasonCode = "EVIDENCE_EXPIRED"
	ReasonConfidenceMissing   QualificationReasonCode = "CONFIDENCE_MISSING"
	ReasonConfidenceLow       QualificationReasonCode = "CONFIDENCE_LOW"
	ReasonProvenanceMissing   QualificationReasonCode = "PROVENANCE_MISSING"
	ReasonPayloadFieldMissing QualificationReasonCode = "PAYLOAD_FIELD_MISSING"
	ReasonAcquisitionDenied   QualificationReasonCode = "ACQUISITION_DENIED"
)

type QualificationReason struct {
	Code  QualificationReasonCode `json:"code"`
	Field string                  `json:"field,omitempty"`
}

type QualificationResult struct {
	EvidenceID    uuid.UUID             `json:"evidence_id,omitempty"`
	Status        QualificationStatus   `json:"status"`
	EvaluatedAt   time.Time             `json:"evaluated_at"`
	PolicyVersion string                `json:"policy_version"`
	Reasons       []QualificationReason `json:"reasons,omitempty"`
}

type QualificationPolicy struct {
	Version                   string
	TrustedSources            map[string]bool
	AllowedTypes              map[Type]bool
	AllowedAcquisitionMethods map[string]bool
	MaxAge                    time.Duration
	FutureTolerance           time.Duration
	RequireConfidence         bool
	MinimumConfidence         *float64
	RequiredProvenance        []string
	RequiredPayloadFields     []string
}

type Qualifier struct {
	policy QualificationPolicy
}

func NewQualifier(policy QualificationPolicy) (*Qualifier, error) {
	policy.Version = strings.TrimSpace(policy.Version)
	if policy.Version == "" {
		return nil, ErrQualificationPolicyVersionRequired
	}
	if policy.MaxAge < 0 {
		return nil, ErrInvalidQualificationMaxAge
	}
	if policy.FutureTolerance < 0 {
		return nil, ErrInvalidQualificationTolerance
	}
	if policy.MinimumConfidence != nil && (*policy.MinimumConfidence < 0 || *policy.MinimumConfidence > 1) {
		return nil, ErrInvalidQualificationConfidence
	}
	policy.TrustedSources = copyStringSet(policy.TrustedSources)
	policy.AllowedTypes = copyTypeSet(policy.AllowedTypes)
	policy.AllowedAcquisitionMethods = copyStringSet(policy.AllowedAcquisitionMethods)
	policy.RequiredProvenance = normalizedKeys(policy.RequiredProvenance)
	policy.RequiredPayloadFields = normalizedKeys(policy.RequiredPayloadFields)
	policy.MinimumConfidence = copyConfidence(policy.MinimumConfidence)
	return &Qualifier{policy: policy}, nil
}

// Qualify evaluates one immutable Evidence Object against a versioned policy.
// A nil object is explicitly unavailable; a present object either qualifies or
// is rejected with a deterministic, machine-readable list of reasons.
func (q *Qualifier) Qualify(object *Object, evaluatedAt time.Time) (QualificationResult, error) {
	if evaluatedAt.IsZero() {
		return QualificationResult{}, ErrQualificationTimeRequired
	}
	result := QualificationResult{
		Status: QualificationQualified, EvaluatedAt: evaluatedAt.UTC(),
		PolicyVersion: q.policy.Version,
	}
	if object == nil {
		result.Status = QualificationUnavailable
		result.Reasons = []QualificationReason{{Code: ReasonEvidenceUnavailable}}
		return result, nil
	}

	snapshot := object.Snapshot()
	result.EvidenceID = snapshot.EvidenceID
	if err := VerifySnapshot(snapshot); err != nil {
		result.Status = QualificationRejected
		result.Reasons = []QualificationReason{{Code: ReasonIntegrityInvalid, Field: "integrity"}}
		return result, nil
	}

	if len(q.policy.TrustedSources) > 0 && !q.policy.TrustedSources[snapshot.SourceID] {
		result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonSourceUntrusted, Field: "source_id"})
	}
	if len(q.policy.AllowedTypes) > 0 && !q.policy.AllowedTypes[snapshot.EvidenceType] {
		result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonTypeNotAllowed, Field: "evidence_type"})
	}
	if snapshot.ObservedAt.After(result.EvaluatedAt.Add(q.policy.FutureTolerance)) {
		result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonTimestampFuture, Field: "observed_at"})
	} else if q.policy.MaxAge > 0 && result.EvaluatedAt.Sub(snapshot.ObservedAt) > q.policy.MaxAge {
		result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonEvidenceExpired, Field: "observed_at"})
	}
	if snapshot.Confidence == nil {
		if q.policy.RequireConfidence || q.policy.MinimumConfidence != nil {
			result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonConfidenceMissing, Field: "confidence"})
		}
	} else if q.policy.MinimumConfidence != nil && *snapshot.Confidence < *q.policy.MinimumConfidence {
		result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonConfidenceLow, Field: "confidence"})
	}
	for _, key := range q.policy.RequiredProvenance {
		if strings.TrimSpace(snapshot.Provenance[key]) == "" {
			result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonProvenanceMissing, Field: key})
		}
	}
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(snapshot.Payload, &payload)
	for _, key := range q.policy.RequiredPayloadFields {
		if value, found := payload[key]; !found || string(value) == "null" {
			result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonPayloadFieldMissing, Field: key})
		}
	}
	method := snapshot.Integrity.AcquisitionMethod
	if len(q.policy.AllowedAcquisitionMethods) > 0 && !q.policy.AllowedAcquisitionMethods[method] {
		result.Reasons = append(result.Reasons, QualificationReason{Code: ReasonAcquisitionDenied, Field: "acquisition_method"})
	}
	if len(result.Reasons) > 0 {
		result.Status = QualificationRejected
	}
	return result, nil
}

func normalizedKeys(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func copyStringSet(values map[string]bool) map[string]bool {
	result := make(map[string]bool, len(values))
	for key, allowed := range values {
		result[strings.TrimSpace(key)] = allowed
	}
	return result
}

func copyTypeSet(values map[Type]bool) map[Type]bool {
	result := make(map[Type]bool, len(values))
	for key, allowed := range values {
		result[key] = allowed
	}
	return result
}

package evaluation

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEvidenceBindingRequired = errors.New("evaluation: evidence binding is required")
	ErrEvidenceSessionMismatch = errors.New("evaluation: evidence session mismatch")
	ErrEvidenceAlreadyBound    = errors.New("evaluation: different evidence set already bound")
	ErrEvidenceBoundAfterRules = errors.New("evaluation: evidence cannot be bound after rule outcomes")
)

type EvidenceQualificationStatus string

const (
	EvidenceQualified   EvidenceQualificationStatus = "QUALIFIED"
	EvidenceRejected    EvidenceQualificationStatus = "REJECTED"
	EvidenceUnavailable EvidenceQualificationStatus = "UNAVAILABLE"
)

func (s EvidenceQualificationStatus) IsValid() bool {
	return s == EvidenceQualified || s == EvidenceRejected || s == EvidenceUnavailable
}

type EvidenceReference struct {
	EvidenceID uuid.UUID
	Status     EvidenceQualificationStatus
	Reasons    []string
}

type EvidenceSetBinding struct {
	SessionID     uuid.UUID
	Status        EvidenceQualificationStatus
	PolicyVersion string
	QualifiedAt   time.Time
	Reasons       []string
	Evidence      []EvidenceReference
}

type EvidenceSetBoundEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Binding      EvidenceSetBinding
	Version      uint64
}

func (e *EvaluationAggregate) BindEvidenceSet(binding EvidenceSetBinding) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state.IsTerminal() {
		return ErrInvalidStateTransition
	}
	if len(e.ruleOutcomes) > 0 {
		return ErrEvidenceBoundAfterRules
	}
	normalized, err := normalizeEvidenceBinding(binding)
	if err != nil {
		return err
	}
	if normalized.SessionID != e.sessionID {
		return ErrEvidenceSessionMismatch
	}
	if e.evidenceBinding != nil {
		if evidenceBindingsEqual(*e.evidenceBinding, normalized) {
			return nil
		}
		return ErrEvidenceAlreadyBound
	}
	e.evidenceBinding = copyEvidenceBinding(&normalized)
	e.version++
	e.addDomainEvent(EvidenceSetBoundEvent{
		EvaluationID: e.id, SessionID: e.sessionID,
		Binding: normalized, Version: e.version,
	})
	return nil
}

func (e *EvaluationAggregate) EvidenceBinding() *EvidenceSetBinding {
	if e == nil {
		return nil
	}
	return copyEvidenceBinding(e.evidenceBinding)
}

func normalizeEvidenceBinding(binding EvidenceSetBinding) (EvidenceSetBinding, error) {
	binding.PolicyVersion = strings.TrimSpace(binding.PolicyVersion)
	binding.QualifiedAt = binding.QualifiedAt.UTC()
	if binding.SessionID == uuid.Nil || !binding.Status.IsValid() || binding.PolicyVersion == "" || binding.QualifiedAt.IsZero() {
		return EvidenceSetBinding{}, ErrEvidenceBindingRequired
	}
	var err error
	binding.Reasons, err = normalizeEvidenceReasons(binding.Reasons)
	if err != nil {
		return EvidenceSetBinding{}, err
	}
	binding.Evidence = append([]EvidenceReference(nil), binding.Evidence...)
	seen := make(map[uuid.UUID]struct{}, len(binding.Evidence))
	for index := range binding.Evidence {
		reference := &binding.Evidence[index]
		if reference.EvidenceID == uuid.Nil || !reference.Status.IsValid() {
			return EvidenceSetBinding{}, ErrEvidenceBindingRequired
		}
		if _, found := seen[reference.EvidenceID]; found {
			return EvidenceSetBinding{}, ErrEvidenceBindingRequired
		}
		seen[reference.EvidenceID] = struct{}{}
		reference.Reasons, err = normalizeEvidenceReasons(reference.Reasons)
		if err != nil {
			return EvidenceSetBinding{}, err
		}
		if reference.Status == EvidenceQualified && len(reference.Reasons) > 0 {
			return EvidenceSetBinding{}, ErrEvidenceBindingRequired
		}
		if reference.Status != EvidenceQualified && len(reference.Reasons) == 0 {
			return EvidenceSetBinding{}, ErrEvidenceBindingRequired
		}
	}
	if binding.Status == EvidenceQualified {
		if len(binding.Evidence) == 0 || len(binding.Reasons) > 0 {
			return EvidenceSetBinding{}, ErrEvidenceBindingRequired
		}
		for _, reference := range binding.Evidence {
			if reference.Status != EvidenceQualified {
				return EvidenceSetBinding{}, ErrEvidenceBindingRequired
			}
		}
	}
	if binding.Status == EvidenceUnavailable && (len(binding.Evidence) > 0 || len(binding.Reasons) == 0) {
		return EvidenceSetBinding{}, ErrEvidenceBindingRequired
	}
	if binding.Status == EvidenceRejected {
		rejected := len(binding.Reasons) > 0
		for _, reference := range binding.Evidence {
			rejected = rejected || reference.Status != EvidenceQualified
		}
		if !rejected {
			return EvidenceSetBinding{}, ErrEvidenceBindingRequired
		}
	}
	return binding, nil
}

func normalizeEvidenceReasons(reasons []string) ([]string, error) {
	result := make([]string, 0, len(reasons))
	seen := make(map[string]struct{}, len(reasons))
	for _, reason := range reasons {
		reason = strings.ToUpper(strings.TrimSpace(reason))
		if reason == "" {
			continue
		}
		if !reasonCodePattern.MatchString(reason) {
			return nil, ErrEvidenceBindingRequired
		}
		if _, found := seen[reason]; found {
			continue
		}
		seen[reason] = struct{}{}
		result = append(result, reason)
	}
	return result, nil
}

func copyEvidenceBinding(source *EvidenceSetBinding) *EvidenceSetBinding {
	if source == nil {
		return nil
	}
	result := *source
	result.Reasons = append([]string(nil), source.Reasons...)
	result.Evidence = append([]EvidenceReference(nil), source.Evidence...)
	for index := range result.Evidence {
		result.Evidence[index].Reasons = append([]string(nil), source.Evidence[index].Reasons...)
	}
	return &result
}

func evidenceBindingsEqual(left, right EvidenceSetBinding) bool {
	if left.SessionID != right.SessionID || left.Status != right.Status || left.PolicyVersion != right.PolicyVersion ||
		!left.QualifiedAt.Equal(right.QualifiedAt) || len(left.Reasons) != len(right.Reasons) || len(left.Evidence) != len(right.Evidence) {
		return false
	}
	for index := range left.Reasons {
		if left.Reasons[index] != right.Reasons[index] {
			return false
		}
	}
	for index := range left.Evidence {
		l, r := left.Evidence[index], right.Evidence[index]
		if l.EvidenceID != r.EvidenceID || l.Status != r.Status || len(l.Reasons) != len(r.Reasons) {
			return false
		}
		for reasonIndex := range l.Reasons {
			if l.Reasons[reasonIndex] != r.Reasons[reasonIndex] {
				return false
			}
		}
	}
	return true
}

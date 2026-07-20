package evaluation

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrPolicyBindingRequired = errors.New("evaluation: verification policy binding is required")
	ErrPolicyAlreadyBound    = errors.New("evaluation: different verification policy already bound")
	ErrPolicyBoundAfterRules = errors.New("evaluation: verification policy cannot be bound after rule outcomes")
)

var policyHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type PolicyBinding struct {
	PolicyID string
	Version  string
	Hash     string
	BoundAt  time.Time
}

type VerificationPolicyBoundEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Binding      PolicyBinding
	Version      uint64
}

func (e *EvaluationAggregate) BindVerificationPolicy(binding PolicyBinding) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state.IsTerminal() {
		return ErrInvalidStateTransition
	}
	if len(e.ruleOutcomes) > 0 {
		return ErrPolicyBoundAfterRules
	}
	normalized, err := normalizePolicyBinding(binding)
	if err != nil || normalized.BoundAt.Before(e.createdAt) {
		return ErrPolicyBindingRequired
	}
	if e.policyBinding != nil {
		if *e.policyBinding == normalized {
			return nil
		}
		return ErrPolicyAlreadyBound
	}
	e.policyBinding = copyPolicyBinding(&normalized)
	e.version++
	e.addDomainEvent(VerificationPolicyBoundEvent{
		EvaluationID: e.id, SessionID: e.sessionID,
		Binding: normalized, Version: e.version,
	})
	return nil
}

func (e *EvaluationAggregate) PolicyBinding() *PolicyBinding {
	if e == nil {
		return nil
	}
	return copyPolicyBinding(e.policyBinding)
}

func normalizePolicyBinding(binding PolicyBinding) (PolicyBinding, error) {
	binding.PolicyID = strings.TrimSpace(binding.PolicyID)
	binding.Version = strings.TrimSpace(binding.Version)
	binding.Hash = strings.TrimSpace(binding.Hash)
	binding.BoundAt = binding.BoundAt.UTC()
	if binding.PolicyID == "" || binding.Version == "" || !policyHashPattern.MatchString(binding.Hash) || binding.BoundAt.IsZero() {
		return PolicyBinding{}, ErrPolicyBindingRequired
	}
	return binding, nil
}

func copyPolicyBinding(source *PolicyBinding) *PolicyBinding {
	if source == nil {
		return nil
	}
	copy := *source
	return &copy
}

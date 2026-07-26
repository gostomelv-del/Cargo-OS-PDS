package policy

import (
	"context"
	"errors"
	"time"
)

var (
	ErrPolicyRegistryRequired      = errors.New("policy: registry is required")
	ErrDocumentValidatorRequired   = errors.New("policy: document validator is required")
	ErrVerificationAfterActivation = errors.New("policy: verification must not occur after activation")
)

// ActivatedVersionRegistry is the persistence boundary for policies that have
// passed signature verification and approval.
type ActivatedVersionRegistry interface {
	Add(context.Context, *ActivatedVersion) error
}

// DocumentValidator verifies every executable rule in an immutable policy
// document before that version can become active.
type DocumentValidator interface {
	ValidatePolicyDocument(context.Context, *Version) error
}

// AdmissionService provides the single fail-closed path from an immutable
// policy version to an active registry entry.
type AdmissionService struct {
	verifier  *Verifier
	validator DocumentValidator
	registry  ActivatedVersionRegistry
}

func NewAdmissionService(
	verifier *Verifier,
	validator DocumentValidator,
	registry ActivatedVersionRegistry,
) (*AdmissionService, error) {
	if verifier == nil || verifier.trustStore == nil {
		return nil, ErrTrustStoreRequired
	}
	if validator == nil {
		return nil, ErrDocumentValidatorRequired
	}
	if registry == nil {
		return nil, ErrPolicyRegistryRequired
	}
	return &AdmissionService{verifier: verifier, validator: validator, registry: registry}, nil
}

func (s *AdmissionService) Admit(
	ctx context.Context,
	version *Version,
	signature Signature,
	approval ApprovalRecord,
	verifiedAt time.Time,
	activatedAt time.Time,
) (*ActivatedVersion, error) {
	if s == nil || s.verifier == nil || s.verifier.trustStore == nil {
		return nil, ErrTrustStoreRequired
	}
	if s.registry == nil {
		return nil, ErrPolicyRegistryRequired
	}
	if s.validator == nil {
		return nil, ErrDocumentValidatorRequired
	}
	verifiedAt = verifiedAt.UTC()
	activatedAt = activatedAt.UTC()
	if !verifiedAt.IsZero() && !activatedAt.IsZero() && verifiedAt.After(activatedAt) {
		return nil, ErrVerificationAfterActivation
	}
	verified, err := s.verifier.Verify(ctx, version, signature, verifiedAt)
	if err != nil {
		return nil, err
	}
	if err = s.validator.ValidatePolicyDocument(ctx, verified.Version()); err != nil {
		return nil, err
	}
	activated, err := Activate(verified, approval, activatedAt)
	if err != nil {
		return nil, err
	}
	if err = s.registry.Add(ctx, activated); err != nil {
		return nil, err
	}
	return activated, nil
}

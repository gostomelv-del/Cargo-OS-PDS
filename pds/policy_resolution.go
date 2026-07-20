package pds

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/policy"
)

var (
	ErrPolicyResolverRequired = errors.New("pds: policy resolver is required")
	ErrPolicyRulePlanMismatch = errors.New("pds: resolved policy rule plan differs from evaluation")
)

type PolicyResolver interface {
	Resolve(context.Context, string, time.Time) (*policy.Version, error)
}

func (s *Service) ResolveAndBindPolicy(ctx context.Context, evaluationID uuid.UUID, policyID string, resolver PolicyResolver) (evaluation.EvaluationSnapshot, error) {
	if resolver == nil {
		return evaluation.EvaluationSnapshot{}, ErrPolicyResolverRequired
	}
	aggregate, err := s.find(ctx, evaluationID)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	expectedVersion := aggregate.Version()
	snapshot, err := aggregate.Snapshot()
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	resolved, err := resolver.Resolve(ctx, policyID, snapshot.CreatedAt)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	policySnapshot := resolved.Snapshot()
	if !sameRulePlan(snapshot.RequiredRuleIDs, policySnapshot.RequiredRuleIDs) {
		return evaluation.EvaluationSnapshot{}, ErrPolicyRulePlanMismatch
	}
	if err = aggregate.BindVerificationPolicy(evaluation.PolicyBinding{
		PolicyID: policySnapshot.PolicyID, Version: policySnapshot.Version,
		Hash: policySnapshot.Hash, BoundAt: s.now().UTC(),
	}); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if err = s.save(ctx, aggregate, expectedVersion); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	return aggregate.Snapshot()
}

func sameRulePlan(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

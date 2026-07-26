package pds

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
)

var (
	ErrTimeoutPolicyInvalid  = errors.New("pds: timeout policy is invalid")
	ErrEvaluationNotTimedOut = errors.New("pds: evaluation has not timed out")
)

// TimeoutPolicy defines server-controlled limits for the two non-terminal
// Evaluation phases. A zero duration disables expiration for that phase.
type TimeoutPolicy struct {
	CreatedTimeout time.Duration
	RunningTimeout time.Duration
}

func (p TimeoutPolicy) Validate() error {
	if p.CreatedTimeout < 0 || p.RunningTimeout < 0 ||
		(p.CreatedTimeout == 0 && p.RunningTimeout == 0) {
		return ErrTimeoutPolicyInvalid
	}
	return nil
}

func (p TimeoutPolicy) deadline(snapshot evaluation.EvaluationSnapshot) (time.Time, error) {
	if err := p.Validate(); err != nil {
		return time.Time{}, err
	}
	switch snapshot.State {
	case evaluation.StateCreated:
		if p.CreatedTimeout == 0 {
			return time.Time{}, ErrTimeoutPolicyInvalid
		}
		return snapshot.CreatedAt.Add(p.CreatedTimeout), nil
	case evaluation.StateRunning:
		if p.RunningTimeout == 0 || snapshot.StartedAt == nil {
			return time.Time{}, ErrTimeoutPolicyInvalid
		}
		return snapshot.StartedAt.Add(p.RunningTimeout), nil
	default:
		return time.Time{}, evaluation.ErrInvalidStateTransition
	}
}

// ExpireTimedOut evaluates an Evaluation against a trusted timeout policy and
// atomically persists one terminal EXPIRED state and outbox event. Exact
// retries return the original snapshot without changing its timestamp,
// version, reason code, or outbox count.
func (s *Service) ExpireTimedOut(
	ctx context.Context,
	id uuid.UUID,
	policy TimeoutPolicy,
) (evaluation.EvaluationSnapshot, error) {
	aggregate, err := s.find(ctx, id)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	current, err := aggregate.Snapshot()
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if current.State == evaluation.StateExpired {
		return current, nil
	}
	deadline, err := policy.deadline(current)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	now := s.now().UTC()
	if now.Before(deadline) {
		return evaluation.EvaluationSnapshot{}, ErrEvaluationNotTimedOut
	}
	expectedVersion := aggregate.Version()
	if err = aggregate.Expire(now); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if err = s.save(ctx, aggregate, expectedVersion); err != nil {
		if errors.Is(err, ErrConcurrentModification) {
			latest, findErr := s.Snapshot(ctx, id)
			if findErr == nil && latest.State == evaluation.StateExpired {
				return latest, nil
			}
		}
		return evaluation.EvaluationSnapshot{}, err
	}
	return aggregate.Snapshot()
}

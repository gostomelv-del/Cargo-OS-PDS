package pds

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
)

var ErrEvaluationNotFound = errors.New("pds: evaluation not found")
var ErrConcurrentModification = errors.New("pds: concurrent modification")

type Clock func() time.Time

type AggregateStore interface {
	SaveEvaluation(
		context.Context,
		evaluation.EvaluationSnapshot,
		uint64,
		[]evaluation.OutboxRecord,
	) error
	FindEvaluation(context.Context, uuid.UUID) (*evaluation.EvaluationAggregate, error)
}

type Service struct {
	store AggregateStore
	now   Clock
}

func NewService(now Clock) *Service {
	return NewServiceWithStore(NewMemoryStore(), now)
}

func NewServiceWithStore(store AggregateStore, now Clock) *Service {
	if store == nil {
		store = NewMemoryStore()
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{store: store, now: now}
}

func (s *Service) Create(
	ctx context.Context,
	sessionID uuid.UUID,
	requiredRules []string,
) (evaluation.EvaluationSnapshot, error) {
	at := s.now().UTC()
	aggregate, err := evaluation.NewEvaluation(uuid.New(), sessionID, at)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	for _, ruleID := range requiredRules {
		if err = aggregate.RegisterRequiredRuleAt(ruleID, at); err != nil {
			return evaluation.EvaluationSnapshot{}, err
		}
	}
	if err = s.save(ctx, aggregate, 0); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	return aggregate.Snapshot()
}

func (s *Service) Start(ctx context.Context, id uuid.UUID) (evaluation.EvaluationSnapshot, error) {
	aggregate, err := s.find(ctx, id)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	expectedVersion := aggregate.Version()
	if err = aggregate.Start(s.now().UTC()); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if err = s.save(ctx, aggregate, expectedVersion); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	return aggregate.Snapshot()
}

func (s *Service) RecordOutcome(
	ctx context.Context,
	id uuid.UUID,
	outcome evaluation.RuleOutcome,
) (evaluation.EvaluationSnapshot, error) {
	aggregate, err := s.find(ctx, id)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	expectedVersion := aggregate.Version()
	if outcome.EvaluatedAt.IsZero() {
		outcome.EvaluatedAt = s.now().UTC()
	}
	if err = aggregate.RecordRuleOutcome(outcome); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if err = s.save(ctx, aggregate, expectedVersion); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	return aggregate.Snapshot()
}

func (s *Service) Complete(ctx context.Context, id uuid.UUID) (evaluation.DecisionTrace, error) {
	aggregate, err := s.find(ctx, id)
	if err != nil {
		return evaluation.DecisionTrace{}, err
	}
	expectedVersion := aggregate.Version()
	result, reasons, err := aggregate.DeriveResult()
	if err != nil {
		return evaluation.DecisionTrace{}, err
	}
	if err = aggregate.CompleteAt(result, reasons, s.now().UTC()); err != nil {
		return evaluation.DecisionTrace{}, err
	}
	if err = s.save(ctx, aggregate, expectedVersion); err != nil {
		return evaluation.DecisionTrace{}, err
	}
	return aggregate.DecisionTrace()
}

func (s *Service) Trace(ctx context.Context, id uuid.UUID) (evaluation.DecisionTrace, error) {
	aggregate, err := s.find(ctx, id)
	if err != nil {
		return evaluation.DecisionTrace{}, err
	}
	return aggregate.DecisionTrace()
}

func (s *Service) find(
	ctx context.Context,
	id uuid.UUID,
) (*evaluation.EvaluationAggregate, error) {
	aggregate, err := s.store.FindEvaluation(ctx, id)
	if err != nil {
		return nil, err
	}
	if aggregate == nil {
		return nil, ErrEvaluationNotFound
	}
	return aggregate, nil
}

func (s *Service) save(
	ctx context.Context,
	aggregate *evaluation.EvaluationAggregate,
	expectedVersion uint64,
) error {
	snapshot, err := aggregate.Snapshot()
	if err != nil {
		return err
	}
	records, err := aggregate.BuildOutboxRecords(s.now().UTC())
	if err != nil {
		return err
	}
	if err = s.store.SaveEvaluation(ctx, snapshot, expectedVersion, records); err != nil {
		return err
	}
	aggregate.ClearDomainEvents()
	return nil
}

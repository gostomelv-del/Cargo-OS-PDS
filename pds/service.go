package pds

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
)

var ErrEvaluationNotFound = errors.New("pds: evaluation not found")

type Clock func() time.Time

type Service struct {
	mu          sync.RWMutex
	evaluations map[uuid.UUID]*evaluation.EvaluationAggregate
	now         Clock
}

func NewService(now Clock) *Service {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{evaluations: make(map[uuid.UUID]*evaluation.EvaluationAggregate), now: now}
}

func (s *Service) Create(sessionID uuid.UUID, requiredRules []string) (evaluation.EvaluationSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.evaluations[aggregate.ID()] = aggregate
	return aggregate.Snapshot()
}

func (s *Service) Start(id uuid.UUID) (evaluation.EvaluationSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aggregate, err := s.find(id)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if err = aggregate.Start(s.now().UTC()); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	return aggregate.Snapshot()
}

func (s *Service) RecordOutcome(id uuid.UUID, outcome evaluation.RuleOutcome) (evaluation.EvaluationSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aggregate, err := s.find(id)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if outcome.EvaluatedAt.IsZero() {
		outcome.EvaluatedAt = s.now().UTC()
	}
	if err = aggregate.RecordRuleOutcome(outcome); err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	return aggregate.Snapshot()
}

func (s *Service) Complete(id uuid.UUID) (evaluation.DecisionTrace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aggregate, err := s.find(id)
	if err != nil {
		return evaluation.DecisionTrace{}, err
	}
	result, reasons, err := aggregate.DeriveResult()
	if err != nil {
		return evaluation.DecisionTrace{}, err
	}
	if err = aggregate.CompleteAt(result, reasons, s.now().UTC()); err != nil {
		return evaluation.DecisionTrace{}, err
	}
	return aggregate.DecisionTrace()
}

func (s *Service) Trace(id uuid.UUID) (evaluation.DecisionTrace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	aggregate, err := s.find(id)
	if err != nil {
		return evaluation.DecisionTrace{}, err
	}
	return aggregate.DecisionTrace()
}

func (s *Service) find(id uuid.UUID) (*evaluation.EvaluationAggregate, error) {
	aggregate, ok := s.evaluations[id]
	if !ok {
		return nil, ErrEvaluationNotFound
	}
	return aggregate, nil
}

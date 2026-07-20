package ruleoperator

import (
	"context"
	"errors"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
)

var ErrMinimumCountRequired = errors.New("ruleoperator: minimum evidence count must be greater than zero")

const reasonEvidenceCountBelowMinimum evaluation.ReasonCode = "EVIDENCE_COUNT_BELOW_MINIMUM"

// ExistenceOperator verifies that a qualified RuleInput contains at least the
// configured number of observations for one Evidence type and optional source.
type ExistenceOperator struct {
	ruleID       string
	evidenceType evidence.Type
	sourceID     string
	minimumCount uint32
}

func NewExistenceOperator(ruleID string, evidenceType evidence.Type, sourceID string, minimumCount uint32) (*ExistenceOperator, error) {
	var err error
	if ruleID, err = normalizeRuleID(ruleID); err != nil {
		return nil, err
	}
	selector, err := normalizeSelector(Selector{EvidenceType: evidenceType, SourceID: sourceID})
	if err != nil {
		return nil, err
	}
	if minimumCount == 0 {
		return nil, ErrMinimumCountRequired
	}
	return &ExistenceOperator{
		ruleID: ruleID, evidenceType: selector.EvidenceType,
		sourceID: selector.SourceID, minimumCount: minimumCount,
	}, nil
}

func (o *ExistenceOperator) RuleID() string { return o.ruleID }

func (o *ExistenceOperator) Evaluate(_ context.Context, input pds.RuleInput) (pds.RuleDecision, error) {
	var count uint32
	for _, snapshot := range input.Evidence {
		if snapshot.EvidenceType == o.evidenceType && (o.sourceID == "" || snapshot.SourceID == o.sourceID) {
			count++
		}
	}
	if count < o.minimumCount {
		return fail(reasonEvidenceCountBelowMinimum), nil
	}
	return pass(), nil
}

var _ pds.RuleOperator = (*ExistenceOperator)(nil)

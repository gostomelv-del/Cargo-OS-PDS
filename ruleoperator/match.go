package ruleoperator

import (
	"bytes"
	"context"
	"encoding/json"

	"cargoos/pds"
)

type MatchOperator struct {
	ruleID   string
	selector Selector
	expected []byte
}

func NewMatchOperator(ruleID string, selector Selector, expected json.RawMessage) (*MatchOperator, error) {
	var err error
	if ruleID, err = normalizeRuleID(ruleID); err != nil {
		return nil, err
	}
	if selector, err = normalizeSelector(selector); err != nil {
		return nil, err
	}
	value, err := decodeJSON(expected)
	if err != nil {
		return nil, ErrInvalidExpectedValue
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidExpectedValue
	}
	return &MatchOperator{ruleID: ruleID, selector: selector, expected: canonical}, nil
}

func (o *MatchOperator) RuleID() string { return o.ruleID }

func (o *MatchOperator) Evaluate(_ context.Context, input pds.RuleInput) (pds.RuleDecision, error) {
	value, unavailable := selectValue(input, o.selector)
	if unavailable != nil {
		return *unavailable, nil
	}
	actual, err := json.Marshal(value)
	if err != nil {
		return *inconclusive(reasonInvalidValue), nil
	}
	if !bytes.Equal(actual, o.expected) {
		return fail(reasonMatchMismatch), nil
	}
	return pass(), nil
}

var _ pds.RuleOperator = (*MatchOperator)(nil)

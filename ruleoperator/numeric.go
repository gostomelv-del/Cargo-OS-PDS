package ruleoperator

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"

	"cargoos/pds"
)

type RangeOperator struct {
	ruleID   string
	selector Selector
	minimum  *big.Rat
	maximum  *big.Rat
}

func NewRangeOperator(ruleID string, selector Selector, minimum, maximum string) (*RangeOperator, error) {
	var err error
	if ruleID, err = normalizeRuleID(ruleID); err != nil {
		return nil, err
	}
	if selector, err = normalizeSelector(selector); err != nil {
		return nil, err
	}
	min, err := decimal(minimum)
	if err != nil {
		return nil, err
	}
	max, err := decimal(maximum)
	if err != nil {
		return nil, err
	}
	if min.Cmp(max) > 0 {
		return nil, ErrInvalidRange
	}
	return &RangeOperator{ruleID: ruleID, selector: selector, minimum: min, maximum: max}, nil
}

func (o *RangeOperator) RuleID() string { return o.ruleID }

func (o *RangeOperator) Evaluate(_ context.Context, input pds.RuleInput) (pds.RuleDecision, error) {
	value, unavailable := selectValue(input, o.selector)
	if unavailable != nil {
		return *unavailable, nil
	}
	actual, err := numericValue(value)
	if err != nil {
		return *inconclusive(reasonInvalidValue), nil
	}
	if actual.Cmp(o.minimum) < 0 || actual.Cmp(o.maximum) > 0 {
		return fail(reasonOutsideRange), nil
	}
	return pass(), nil
}

type ToleranceOperator struct {
	ruleID    string
	selector  Selector
	expected  *big.Rat
	tolerance *big.Rat
}

func NewToleranceOperator(ruleID string, selector Selector, expected, tolerance string) (*ToleranceOperator, error) {
	var err error
	if ruleID, err = normalizeRuleID(ruleID); err != nil {
		return nil, err
	}
	if selector, err = normalizeSelector(selector); err != nil {
		return nil, err
	}
	target, err := decimal(expected)
	if err != nil {
		return nil, err
	}
	delta, err := decimal(tolerance)
	if err != nil {
		return nil, err
	}
	if delta.Sign() < 0 {
		return nil, ErrInvalidTolerance
	}
	return &ToleranceOperator{ruleID: ruleID, selector: selector, expected: target, tolerance: delta}, nil
}

func (o *ToleranceOperator) RuleID() string { return o.ruleID }

func (o *ToleranceOperator) Evaluate(_ context.Context, input pds.RuleInput) (pds.RuleDecision, error) {
	value, unavailable := selectValue(input, o.selector)
	if unavailable != nil {
		return *unavailable, nil
	}
	actual, err := numericValue(value)
	if err != nil {
		return *inconclusive(reasonInvalidValue), nil
	}
	difference := new(big.Rat).Sub(actual, o.expected)
	if difference.Sign() < 0 {
		difference.Neg(difference)
	}
	if difference.Cmp(o.tolerance) > 0 {
		return fail(reasonOutsideTolerance), nil
	}
	return pass(), nil
}

func numericValue(value any) (*big.Rat, error) {
	number, ok := value.(json.Number)
	if !ok {
		return nil, ErrInvalidNumericValue
	}
	return decimal(number.String())
}

func decimal(value string) (*big.Rat, error) {
	value = strings.TrimSpace(value)
	decoded, err := decodeJSON([]byte(value))
	if err != nil {
		return nil, ErrInvalidNumericValue
	}
	number, ok := decoded.(json.Number)
	if !ok {
		return nil, ErrInvalidNumericValue
	}
	result, ok := new(big.Rat).SetString(number.String())
	if !ok {
		return nil, ErrInvalidNumericValue
	}
	return result, nil
}

var _ pds.RuleOperator = (*RangeOperator)(nil)
var _ pds.RuleOperator = (*ToleranceOperator)(nil)

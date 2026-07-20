package ruleoperator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
)

var (
	ErrSequenceStepsRequired = errors.New("ruleoperator: sequence requires at least two steps")
	ErrInvalidSequenceWindow = errors.New("ruleoperator: sequence windows must not be negative")
)

const (
	reasonSequenceIncomplete       evaluation.ReasonCode = "SEQUENCE_INCOMPLETE"
	reasonSequenceOrderInvalid     evaluation.ReasonCode = "SEQUENCE_ORDER_INVALID"
	reasonSequenceValueMismatch    evaluation.ReasonCode = "SEQUENCE_VALUE_MISMATCH"
	reasonSequenceGapExceeded      evaluation.ReasonCode = "SEQUENCE_GAP_EXCEEDED"
	reasonSequenceDurationExceeded evaluation.ReasonCode = "SEQUENCE_DURATION_EXCEEDED"
)

type SequenceStep struct {
	Selector Selector
	Expected json.RawMessage
}

type sequenceStep struct {
	selector Selector
	expected []byte
}

type SequenceOperator struct {
	ruleID      string
	steps       []sequenceStep
	maxGap      time.Duration
	maxDuration time.Duration
}

func NewSequenceOperator(ruleID string, steps []SequenceStep, maxGap, maxDuration time.Duration) (*SequenceOperator, error) {
	var err error
	if ruleID, err = normalizeRuleID(ruleID); err != nil {
		return nil, err
	}
	if len(steps) < 2 {
		return nil, ErrSequenceStepsRequired
	}
	if maxGap < 0 || maxDuration < 0 {
		return nil, ErrInvalidSequenceWindow
	}
	normalized := make([]sequenceStep, 0, len(steps))
	for _, step := range steps {
		selector, selectorErr := normalizeSelector(step.Selector)
		if selectorErr != nil {
			return nil, selectorErr
		}
		value, valueErr := decodeJSON(step.Expected)
		if valueErr != nil {
			return nil, ErrInvalidExpectedValue
		}
		expected, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return nil, ErrInvalidExpectedValue
		}
		normalized = append(normalized, sequenceStep{selector: selector, expected: expected})
	}
	return &SequenceOperator{ruleID: ruleID, steps: normalized, maxGap: maxGap, maxDuration: maxDuration}, nil
}

func (o *SequenceOperator) RuleID() string { return o.ruleID }

func (o *SequenceOperator) Evaluate(_ context.Context, input pds.RuleInput) (pds.RuleDecision, error) {
	ordered := append([]evidence.Snapshot(nil), input.Evidence...)
	sort.SliceStable(ordered, func(left, right int) bool {
		if ordered[left].ObservedAt.Equal(ordered[right].ObservedAt) {
			return ordered[left].EvidenceID.String() < ordered[right].EvidenceID.String()
		}
		return ordered[left].ObservedAt.Before(ordered[right].ObservedAt)
	})
	previousIndex := -1
	var firstAt, previousAt time.Time
	for _, step := range o.steps {
		index := nextMatchingEvidence(ordered, step.selector, previousIndex+1)
		if index < 0 {
			if nextMatchingEvidence(ordered, step.selector, 0) >= 0 {
				return fail(reasonSequenceOrderInvalid), nil
			}
			return *inconclusive(reasonSequenceIncomplete), nil
		}
		value, reason := valueAtSnapshot(ordered[index], step.selector.JSONPointer)
		if reason != "" {
			return *inconclusive(reason), nil
		}
		actual, err := json.Marshal(value)
		if err != nil {
			return *inconclusive(reasonInvalidValue), nil
		}
		if !bytes.Equal(actual, step.expected) {
			return fail(reasonSequenceValueMismatch), nil
		}
		observedAt := ordered[index].ObservedAt.UTC()
		if previousIndex < 0 {
			firstAt = observedAt
		} else if o.maxGap > 0 && observedAt.Sub(previousAt) > o.maxGap {
			return fail(reasonSequenceGapExceeded), nil
		}
		if o.maxDuration > 0 && observedAt.Sub(firstAt) > o.maxDuration {
			return fail(reasonSequenceDurationExceeded), nil
		}
		previousIndex = index
		previousAt = observedAt
	}
	return pass(), nil
}

func nextMatchingEvidence(ordered []evidence.Snapshot, selector Selector, start int) int {
	for index := start; index < len(ordered); index++ {
		if selectorMatches(ordered[index], selector) {
			return index
		}
	}
	return -1
}

var _ pds.RuleOperator = (*SequenceOperator)(nil)

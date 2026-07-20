package ruleoperator

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
)

var (
	ErrRuleIDRequired       = errors.New("ruleoperator: rule ID is required")
	ErrEvidenceTypeRequired = errors.New("ruleoperator: evidence type is required")
	ErrInvalidJSONPointer   = errors.New("ruleoperator: invalid JSON pointer")
	ErrInvalidExpectedValue = errors.New("ruleoperator: expected value must be one JSON value")
	ErrInvalidNumericValue  = errors.New("ruleoperator: invalid decimal value")
	ErrInvalidRange         = errors.New("ruleoperator: minimum exceeds maximum")
	ErrInvalidTolerance     = errors.New("ruleoperator: tolerance must not be negative")
)

const (
	reasonEvidenceNotFound  evaluation.ReasonCode = "EVIDENCE_NOT_FOUND"
	reasonEvidenceAmbiguous evaluation.ReasonCode = "EVIDENCE_AMBIGUOUS"
	reasonFieldNotFound     evaluation.ReasonCode = "FIELD_NOT_FOUND"
	reasonInvalidValue      evaluation.ReasonCode = "INVALID_VALUE"
	reasonMatchMismatch     evaluation.ReasonCode = "MATCH_MISMATCH"
	reasonOutsideRange      evaluation.ReasonCode = "VALUE_OUT_OF_RANGE"
	reasonOutsideTolerance  evaluation.ReasonCode = "VALUE_OUTSIDE_TOLERANCE"
)

type Selector struct {
	EvidenceType evidence.Type
	SourceID     string
	JSONPointer  string
}

func normalizeSelector(selector Selector) (Selector, error) {
	selector.SourceID = strings.TrimSpace(selector.SourceID)
	selector.JSONPointer = strings.TrimSpace(selector.JSONPointer)
	if strings.TrimSpace(string(selector.EvidenceType)) == "" {
		return Selector{}, ErrEvidenceTypeRequired
	}
	if selector.JSONPointer != "" && !strings.HasPrefix(selector.JSONPointer, "/") {
		return Selector{}, ErrInvalidJSONPointer
	}
	for _, token := range strings.Split(strings.TrimPrefix(selector.JSONPointer, "/"), "/") {
		for index := 0; index < len(token); index++ {
			if token[index] == '~' && (index+1 >= len(token) || (token[index+1] != '0' && token[index+1] != '1')) {
				return Selector{}, ErrInvalidJSONPointer
			}
			if token[index] == '~' {
				index++
			}
		}
	}
	return selector, nil
}

func normalizeRuleID(ruleID string) (string, error) {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return "", ErrRuleIDRequired
	}
	return ruleID, nil
}

func selectValue(input pds.RuleInput, selector Selector) (any, *pds.RuleDecision) {
	matches := make([]evidence.Snapshot, 0, 1)
	for _, snapshot := range input.Evidence {
		if snapshot.EvidenceType == selector.EvidenceType && (selector.SourceID == "" || snapshot.SourceID == selector.SourceID) {
			matches = append(matches, snapshot)
		}
	}
	if len(matches) == 0 {
		return nil, inconclusive(reasonEvidenceNotFound)
	}
	if len(matches) > 1 {
		return nil, inconclusive(reasonEvidenceAmbiguous)
	}
	value, err := decodeJSON(matches[0].Payload)
	if err != nil {
		return nil, inconclusive(reasonInvalidValue)
	}
	if selector.JSONPointer == "" {
		return value, nil
	}
	for _, encoded := range strings.Split(strings.TrimPrefix(selector.JSONPointer, "/"), "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch current := value.(type) {
		case map[string]any:
			var found bool
			value, found = current[token]
			if !found {
				return nil, inconclusive(reasonFieldNotFound)
			}
		case []any:
			index, parseErr := strconv.Atoi(token)
			if parseErr != nil || index < 0 || index >= len(current) {
				return nil, inconclusive(reasonFieldNotFound)
			}
			value = current[index]
		default:
			return nil, inconclusive(reasonFieldNotFound)
		}
	}
	return value, nil
}

func decodeJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidExpectedValue
	}
	return value, nil
}

func inconclusive(reason evaluation.ReasonCode) *pds.RuleDecision {
	return &pds.RuleDecision{Status: evaluation.RuleOutcomeInconclusive, ReasonCodes: []evaluation.ReasonCode{reason}}
}

func fail(reason evaluation.ReasonCode) pds.RuleDecision {
	return pds.RuleDecision{Status: evaluation.RuleOutcomeFail, ReasonCodes: []evaluation.ReasonCode{reason}}
}

func pass() pds.RuleDecision {
	return pds.RuleDecision{Status: evaluation.RuleOutcomePass}
}

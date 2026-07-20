package ruleoperator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
)

func operatorEvidence(t *testing.T, evidenceType evidence.Type, sourceID, payload string) evidence.Snapshot {
	t.Helper()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	object, err := evidence.NewObject(evidence.Input{
		EvidenceID: uuid.New(), SessionID: uuid.New(), SourceID: sourceID,
		SourceType: "TEST_SENSOR", EvidenceType: evidenceType,
		ObservedAt: now, ReceivedAt: now, Payload: json.RawMessage(payload),
		SchemaVersion: "evidence.v1", RuntimeVersion: "test", AcquisitionMethod: "TEST",
	})
	if err != nil {
		t.Fatal(err)
	}
	return object.Snapshot()
}

func ruleInput(snapshots ...evidence.Snapshot) pds.RuleInput {
	return pds.RuleInput{EvaluationID: uuid.New(), SessionID: uuid.New(), PolicyVersion: "policy.v1", Evidence: snapshots}
}

func TestMatchOperatorUsesJSONPointerAndCanonicalValues(t *testing.T) {
	operator, err := NewMatchOperator("destination", Selector{
		EvidenceType: evidence.TypePosition, SourceID: "scanner-1", JSONPointer: "/target/code",
	}, json.RawMessage(`"A-17"`))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypePosition, "scanner-1", `{"target":{"code":"A-17"}}`),
	))
	if err != nil || decision.Status != evaluation.RuleOutcomePass {
		t.Fatalf("expected match pass, got %#v, %v", decision, err)
	}

	decision, err = operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypePosition, "scanner-1", `{"target":{"code":"B-02"}}`),
	))
	if err != nil || decision.Status != evaluation.RuleOutcomeFail || decision.ReasonCodes[0] != reasonMatchMismatch {
		t.Fatalf("expected match failure, got %#v, %v", decision, err)
	}
}

func TestSelectorFailsClosedForMissingAndAmbiguousEvidence(t *testing.T) {
	operator, _ := NewMatchOperator("weight-unit", Selector{
		EvidenceType: evidence.TypeWeight, JSONPointer: "/unit",
	}, json.RawMessage(`"kg"`))
	decision, _ := operator.Evaluate(context.Background(), ruleInput())
	if decision.Status != evaluation.RuleOutcomeInconclusive || decision.ReasonCodes[0] != reasonEvidenceNotFound {
		t.Fatalf("unexpected missing result: %#v", decision)
	}
	one := operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"unit":"kg"}`)
	two := operatorEvidence(t, evidence.TypeWeight, "scale-2", `{"unit":"kg"}`)
	decision, _ = operator.Evaluate(context.Background(), ruleInput(one, two))
	if decision.Status != evaluation.RuleOutcomeInconclusive || decision.ReasonCodes[0] != reasonEvidenceAmbiguous {
		t.Fatalf("unexpected ambiguous result: %#v", decision)
	}
}

func TestRangeOperatorUsesInclusiveExactDecimalBounds(t *testing.T) {
	operator, err := NewRangeOperator("weight-range", Selector{
		EvidenceType: evidence.TypeWeight, JSONPointer: "/value",
	}, "0.3000000000000000001", "0.3000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":0.3000000000000000001}`),
	))
	if decision.Status != evaluation.RuleOutcomePass {
		t.Fatalf("exact boundary did not pass: %#v", decision)
	}
	decision, _ = operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":0.3000000000000000002}`),
	))
	if decision.Status != evaluation.RuleOutcomeFail || decision.ReasonCodes[0] != reasonOutsideRange {
		t.Fatalf("out-of-range value did not fail: %#v", decision)
	}
}

func TestToleranceOperatorUsesAbsoluteExactDifference(t *testing.T) {
	operator, err := NewToleranceOperator("weight-tolerance", Selector{
		EvidenceType: evidence.TypeWeight, JSONPointer: "/value",
	}, "25", "0.05")
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":24.95}`),
	))
	if decision.Status != evaluation.RuleOutcomePass {
		t.Fatalf("tolerance boundary did not pass: %#v", decision)
	}
	decision, _ = operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":24.949999999999999999}`),
	))
	if decision.Status != evaluation.RuleOutcomeFail || decision.ReasonCodes[0] != reasonOutsideTolerance {
		t.Fatalf("outside tolerance did not fail: %#v", decision)
	}
}

func TestNumericOperatorRejectsNonNumericRuntimeValue(t *testing.T) {
	operator, _ := NewRangeOperator("weight-range", Selector{EvidenceType: evidence.TypeWeight, JSONPointer: "/value"}, "0", "10")
	decision, _ := operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":"5"}`),
	))
	if decision.Status != evaluation.RuleOutcomeInconclusive || decision.ReasonCodes[0] != reasonInvalidValue {
		t.Fatalf("unexpected invalid-number result: %#v", decision)
	}
}

func TestOperatorConfigurationValidation(t *testing.T) {
	selector := Selector{EvidenceType: evidence.TypeWeight, JSONPointer: "/value"}
	if _, err := NewMatchOperator("", selector, json.RawMessage(`1`)); !errors.Is(err, ErrRuleIDRequired) {
		t.Fatalf("expected rule ID error, got %v", err)
	}
	if _, err := NewMatchOperator("match", Selector{EvidenceType: evidence.TypeWeight, JSONPointer: "value"}, json.RawMessage(`1`)); !errors.Is(err, ErrInvalidJSONPointer) {
		t.Fatalf("expected pointer error, got %v", err)
	}
	if _, err := NewRangeOperator("range", selector, "2", "1"); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected range error, got %v", err)
	}
	if _, err := NewRangeOperator("range", selector, "1/2", "1"); !errors.Is(err, ErrInvalidNumericValue) {
		t.Fatalf("expected JSON decimal error, got %v", err)
	}
	if _, err := NewToleranceOperator("tolerance", selector, "1", "-0.1"); !errors.Is(err, ErrInvalidTolerance) {
		t.Fatalf("expected tolerance error, got %v", err)
	}
}

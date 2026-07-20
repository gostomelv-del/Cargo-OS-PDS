package ruleoperator

import (
	"context"
	"errors"
	"testing"

	"cargoos/evaluation"
	"cargoos/evidence"
)

func TestExistenceOperatorPassesAtMinimumCount(t *testing.T) {
	operator, err := NewExistenceOperator("weight-present", evidence.TypeWeight, "scale-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":25}`),
		operatorEvidence(t, evidence.TypeWeight, "scale-2", `{"value":26}`),
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":27}`),
	))
	if err != nil || decision.Status != evaluation.RuleOutcomePass {
		t.Fatalf("expected presence pass, got %#v, %v", decision, err)
	}
}

func TestExistenceOperatorFailsBelowMinimumCount(t *testing.T) {
	operator, _ := NewExistenceOperator("weight-present", evidence.TypeWeight, "scale-1", 2)
	decision, err := operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":25}`),
		operatorEvidence(t, evidence.TypePosition, "scale-1", `{"value":25}`),
		operatorEvidence(t, evidence.TypeWeight, "scale-2", `{"value":25}`),
	))
	if err != nil || decision.Status != evaluation.RuleOutcomeFail || decision.ReasonCodes[0] != reasonEvidenceCountBelowMinimum {
		t.Fatalf("expected minimum-count failure, got %#v, %v", decision, err)
	}
}

func TestExistenceOperatorCanCountEverySource(t *testing.T) {
	operator, _ := NewExistenceOperator("weight-present", evidence.TypeWeight, "", 2)
	decision, _ := operator.Evaluate(context.Background(), ruleInput(
		operatorEvidence(t, evidence.TypeWeight, "scale-1", `{"value":25}`),
		operatorEvidence(t, evidence.TypeWeight, "scale-2", `{"value":26}`),
	))
	if decision.Status != evaluation.RuleOutcomePass {
		t.Fatalf("source-agnostic count did not pass: %#v", decision)
	}
}

func TestExistenceOperatorConfigurationValidation(t *testing.T) {
	if _, err := NewExistenceOperator("presence", "", "", 1); !errors.Is(err, ErrEvidenceTypeRequired) {
		t.Fatalf("expected evidence type error, got %v", err)
	}
	if _, err := NewExistenceOperator("presence", evidence.TypeWeight, "", 0); !errors.Is(err, ErrMinimumCountRequired) {
		t.Fatalf("expected minimum count error, got %v", err)
	}
}

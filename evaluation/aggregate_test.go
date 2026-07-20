package evaluation

import (
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestLifecycleAndDerivation(t *testing.T) {
	base := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	e, err := NewEvaluation(uuid.New(), uuid.New(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = e.RegisterRequiredRule("weight"); err != nil {
		t.Fatal(err)
	}
	rc, _ := NewReasonCode("weight_limit")
	if err = e.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomeFail, ReasonCodes: []ReasonCode{rc}, EvaluatedAt: base.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	r, reasons, err := e.DeriveResult()
	if err != nil {
		t.Fatal(err)
	}
	if r != ResultRejected || len(reasons) != 1 {
		t.Fatalf("unexpected result %s %#v", r, reasons)
	}
	if err = e.CompleteAt(r, reasons, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !e.IsTerminal() || e.State() != StateCompleted {
		t.Fatal("not completed")
	}
}
func TestDuplicateOutcomeIsIdempotent(t *testing.T) {
	base := time.Now().UTC()
	e, _ := NewEvaluation(uuid.New(), uuid.New(), base)
	_ = e.Start(base)
	o := RuleOutcome{RuleID: "r1", Status: RuleOutcomePass, EvaluatedAt: base}
	if err := e.RecordRuleOutcome(o); err != nil {
		t.Fatal(err)
	}
	version := e.Version()
	events := len(e.DomainEvents())
	if err := e.RecordRuleOutcome(o); err != nil {
		t.Fatal(err)
	}
	if e.Version() != version || len(e.DomainEvents()) != events {
		t.Fatal("idempotent retry mutated aggregate")
	}
}

func TestRequiredRulesMustBeComplete(t *testing.T) {
	base := time.Now().UTC()
	e, err := NewEvaluation(uuid.New(), uuid.New(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.RegisterRequiredRuleAt("weight", base); err != nil {
		t.Fatal(err)
	}
	if err = e.RegisterRequiredRuleAt("destination", base); err != nil {
		t.Fatal(err)
	}
	if err = e.Start(base); err != nil {
		t.Fatal(err)
	}
	if err = e.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomePass, EvaluatedAt: base}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = e.DeriveResult(); !errors.Is(err, ErrRequiredRulesIncomplete) {
		t.Fatalf("expected required-rules error, got %v", err)
	}
	if err = e.CompleteAt(ResultVerified, nil, base.Add(time.Second)); !errors.Is(err, ErrRequiredRulesIncomplete) {
		t.Fatalf("expected completion to be rejected, got %v", err)
	}
}

func TestRequiredRulesCannotChangeAfterCompletion(t *testing.T) {
	base := time.Now().UTC()
	e, _ := NewEvaluation(uuid.New(), uuid.New(), base)
	_ = e.Start(base)
	_ = e.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomePass, EvaluatedAt: base})
	_ = e.CompleteAt(ResultVerified, nil, base.Add(time.Second))
	if err := e.RegisterRequiredRuleAt("late-rule", base.Add(2*time.Second)); !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("expected terminal-state rejection, got %v", err)
	}
}

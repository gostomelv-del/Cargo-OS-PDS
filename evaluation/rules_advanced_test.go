package evaluation

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func runningEvaluation(t *testing.T) (*EvaluationAggregate, time.Time) {
	t.Helper()
	base := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	e, err := NewEvaluation(uuid.New(), uuid.New(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	return e, base
}

func pass(rule string, at time.Time) RuleOutcome {
	return RuleOutcome{RuleID: rule, Status: RuleOutcomePass, EvaluatedAt: at}
}

func fail(rule string, at time.Time, code string) RuleOutcome {
	rc, _ := NewReasonCode(code)
	return RuleOutcome{RuleID: rule, Status: RuleOutcomeFail, ReasonCodes: []ReasonCode{rc}, EvaluatedAt: at}
}

func TestRecordRuleOutcomeIdempotentAndConflict(t *testing.T) {
	e, base := runningEvaluation(t)
	o := pass("weight", base.Add(2*time.Second))
	if err := e.RecordRuleOutcome(o); err != nil {
		t.Fatal(err)
	}
	version, events := e.Version(), len(e.DomainEvents())
	if err := e.RecordRuleOutcome(o); err != nil {
		t.Fatal(err)
	}
	if e.Version() != version || len(e.DomainEvents()) != events {
		t.Fatal("idempotent retry mutated aggregate")
	}
	if err := e.RecordRuleOutcome(fail("weight", base.Add(3*time.Second), "WEIGHT_LIMIT")); !errors.Is(err, ErrRuleOutcomeConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestAtomicBatchRejectsWithoutMutation(t *testing.T) {
	e, base := runningEvaluation(t)
	before := e.Version()
	err := e.RecordRuleOutcomesAtomic([]RuleOutcome{
		pass("a", base.Add(2*time.Second)),
		{RuleID: "b", Status: RuleOutcomeFail, EvaluatedAt: base.Add(2 * time.Second)},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if e.Version() != before || len(e.RuleOutcomes()) != 0 {
		t.Fatal("failed batch mutated aggregate")
	}
}

func TestBatchSingleVersionCommit(t *testing.T) {
	e, base := runningEvaluation(t)
	before := e.Version()
	if err := e.RecordRuleOutcomeBatch([]RuleOutcome{
		pass("b", base.Add(2*time.Second)),
		pass("a", base.Add(2*time.Second)),
	}, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if e.Version() != before+1 {
		t.Fatalf("expected one version increment, got %d -> %d", before, e.Version())
	}
	outcomes := e.RuleOutcomes()
	if len(outcomes) != 2 || outcomes[0].RuleID != "a" || outcomes[1].RuleID != "b" {
		t.Fatalf("unexpected outcomes: %#v", outcomes)
	}
}

func TestReplaceRemoveAndReset(t *testing.T) {
	e, base := runningEvaluation(t)
	if err := e.RecordRuleOutcome(pass("a", base.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := e.RecordRuleOutcome(pass("b", base.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := e.ReplaceRuleOutcome(fail("a", base.Add(3*time.Second), "A_FAILED"), base.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, ok := e.RuleOutcomeByID("a")
	if !ok || got.Status != RuleOutcomeFail {
		t.Fatal("replacement not applied")
	}
	if err := e.RemoveRuleOutcome("b", base.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if e.HasRecordedRule("b") {
		t.Fatal("outcome not removed")
	}
	expected := e.Version()
	if err := e.ResetRuleOutcomesAtVersion(expected+1, base.Add(6*time.Second)); !errors.Is(err, ErrEvaluationVersionConflict) {
		t.Fatalf("expected version conflict, got %v", err)
	}
	if err := e.ResetRuleOutcomesAtVersion(expected, base.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if e.HasRuleOutcomes() {
		t.Fatal("reset did not clear outcomes")
	}
}

func TestAtomicRemovalRollback(t *testing.T) {
	e, base := runningEvaluation(t)
	if err := e.RecordRuleOutcome(pass("a", base.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	before := e.Version()
	err := e.RemoveRuleOutcomesAtomic([]string{"a", "missing"}, base.Add(3*time.Second))
	if !errors.Is(err, ErrRuleOutcomeNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	if e.Version() != before || !e.HasRecordedRule("a") {
		t.Fatal("failed removal mutated aggregate")
	}
}

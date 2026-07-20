package evaluation

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newRunningForHistory(t *testing.T) (*EvaluationAggregate, time.Time) {
	t.Helper()
	base := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	e, err := NewEvaluation(uuid.New(), uuid.New(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return e, base
}

func TestCheckpointRollback(t *testing.T) {
	e, base := newRunningForHistory(t)
	if err := e.RecordRuleOutcome(RuleOutcome{RuleID: "R1", Status: RuleOutcomePass, EvaluatedAt: base.Add(2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateCheckpoint("before-warning", base.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	rc, _ := NewReasonCode("SENSOR_WARN")
	if err := e.RecordRuleOutcome(RuleOutcome{RuleID: "R2", Status: RuleOutcomeWarning, ReasonCodes: []ReasonCode{rc}, EvaluatedAt: base.Add(4 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := e.RollbackToCheckpoint("before-warning", base.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if e.HasRecordedRule("R2") {
		t.Fatal("rollback retained R2")
	}
	if !e.HasRecordedRule("R1") {
		t.Fatal("rollback lost R1")
	}
}

func TestHistoryDefensiveCopyAndLookup(t *testing.T) {
	e, base := newRunningForHistory(t)
	if err := e.RecordHistory(base.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	version := e.Version()
	h, err := e.HistoryAtVersion(version)
	if err != nil {
		t.Fatal(err)
	}
	h.RequiredRuleIDs = append(h.RequiredRuleIDs, "MUTATED")
	h2, err := e.HistoryAtVersion(version)
	if err != nil {
		t.Fatal(err)
	}
	if len(h2.RequiredRuleIDs) != 0 {
		t.Fatal("history leaked mutable slice")
	}
	if err := e.RecordHistory(base.Add(3 * time.Minute)); !errors.Is(err, ErrEvaluationHistoryVersionExists) {
		t.Fatalf("expected duplicate version error, got %v", err)
	}
}

func TestAtomicMutationRollsBackWhenHistoryCaptureFails(t *testing.T) {
	e, base := newRunningForHistory(t)
	version := e.Version()
	events := len(e.DomainEvents())
	err := e.ApplyAtomicMutation(time.Time{}, func(a *EvaluationAggregate) error {
		return a.RecordRuleOutcome(RuleOutcome{RuleID: "R1", Status: RuleOutcomePass, EvaluatedAt: base.Add(2 * time.Minute)})
	})
	if !errors.Is(err, ErrHistoryCaptureTimeRequired) {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Version() != version || len(e.DomainEvents()) != events || e.HasRecordedRule("R1") {
		t.Fatal("aggregate was not rolled back")
	}
}

func TestAtomicMutationCommitsWithHistory(t *testing.T) {
	e, base := newRunningForHistory(t)
	err := e.ApplyAtomicMutation(base.Add(3*time.Minute), func(a *EvaluationAggregate) error {
		return a.RecordRuleOutcome(RuleOutcome{RuleID: "R1", Status: RuleOutcomePass, EvaluatedAt: base.Add(2 * time.Minute)})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !e.HasRecordedRule("R1") || len(e.History()) != 1 {
		t.Fatal("mutation or history missing")
	}
}

package evaluation

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSnapshotRehydrateRoundTrip(t *testing.T) {
	base := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	e, err := NewEvaluation(uuid.New(), uuid.New(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.RegisterRequiredRuleAt("weight", base); err != nil {
		t.Fatal(err)
	}
	if err = e.Start(base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = e.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomePass, EvaluatedAt: base.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err = e.CreateCheckpoint("evaluated", base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = e.RecordHistory(base.Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	result, reasons, err := e.DeriveResult()
	if err != nil {
		t.Fatal(err)
	}
	if err = e.CompleteAt(result, reasons, base.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}

	snapshot, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RehydrateEvaluation(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID() != e.ID() || restored.SessionID() != e.SessionID() || restored.Version() != e.Version() {
		t.Fatal("identity or version changed during rehydration")
	}
	if restored.State() != StateCompleted || restored.Result() != ResultVerified {
		t.Fatalf("unexpected restored decision: %s %s", restored.State(), restored.Result())
	}
	if len(restored.DomainEvents()) != 0 {
		t.Fatal("rehydration must not replay domain events")
	}
	if len(restored.Checkpoints()) != 1 || len(restored.History()) != 1 {
		t.Fatal("checkpoint or history was not restored")
	}
}

func TestSnapshotAndTraceAreDefensiveCopies(t *testing.T) {
	base := time.Now().UTC()
	e, _ := NewEvaluation(uuid.New(), uuid.New(), base)
	_ = e.RegisterRequiredRuleAt("weight", base)
	_ = e.Start(base)
	_ = e.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomePass, EvaluatedAt: base})

	snapshot, _ := e.Snapshot()
	trace, _ := e.DecisionTrace()
	snapshot.RequiredRuleIDs[0] = "changed"
	trace.RequiredRuleIDs[0] = "changed"
	trace.RuleOutcomes[0].RuleID = "changed"

	if !e.IsRuleRequired("weight") || e.HasRecordedRule("changed") {
		t.Fatal("snapshot or trace leaked mutable aggregate state")
	}
}

func TestInvalidSnapshotRejected(t *testing.T) {
	_, err := RehydrateEvaluation(EvaluationSnapshot{})
	if !errors.Is(err, ErrInvalidEvaluationSnapshot) {
		t.Fatalf("expected invalid snapshot, got %v", err)
	}

	snapshot := EvaluationSnapshot{
		EvaluationID: uuid.New(),
		SessionID:    uuid.New(),
		State:        StateCreated,
		Result:       ResultUnknown,
		CreatedAt:    time.Now().UTC(),
	}
	_, err = RehydrateEvaluation(snapshot)
	if !errors.Is(err, ErrSnapshotVersionRequired) {
		t.Fatalf("expected version error, got %v", err)
	}
}

func TestDecisionTraceReportsMissingRules(t *testing.T) {
	base := time.Now().UTC()
	e, _ := NewEvaluation(uuid.New(), uuid.New(), base)
	_ = e.RegisterRequiredRuleAt("weight", base)
	_ = e.RegisterRequiredRuleAt("destination", base)
	_ = e.Start(base)
	_ = e.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomePass, EvaluatedAt: base})

	trace, err := e.DecisionTrace()
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.MissingRuleIDs) != 1 || trace.MissingRuleIDs[0] != "destination" {
		t.Fatalf("unexpected missing rules: %#v", trace.MissingRuleIDs)
	}
}

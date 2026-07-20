package evaluation

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testEvidenceBinding(sessionID uuid.UUID, at time.Time) EvidenceSetBinding {
	return EvidenceSetBinding{
		SessionID: sessionID, Status: EvidenceQualified,
		PolicyVersion: "qualification.v1", QualifiedAt: at,
		Evidence: []EvidenceReference{{EvidenceID: uuid.New(), Status: EvidenceQualified}},
	}
}

func TestBindEvidenceSetIsIdempotentAndTraced(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.New()
	aggregate, err := NewEvaluation(uuid.New(), sessionID, base)
	if err != nil {
		t.Fatal(err)
	}
	binding := testEvidenceBinding(sessionID, base.Add(time.Second))
	if err = aggregate.BindEvidenceSet(binding); err != nil {
		t.Fatal(err)
	}
	version := aggregate.Version()
	if err = aggregate.BindEvidenceSet(binding); err != nil || aggregate.Version() != version {
		t.Fatalf("idempotent binding changed aggregate: %v", err)
	}
	trace, err := aggregate.DecisionTrace()
	if err != nil || trace.EvidenceBinding == nil || trace.EvidenceBinding.Evidence[0].EvidenceID != binding.Evidence[0].EvidenceID {
		t.Fatalf("binding missing from trace: %#v, %v", trace, err)
	}
	trace.EvidenceBinding.Evidence[0].Reasons = append(trace.EvidenceBinding.Evidence[0].Reasons, "CHANGED")
	if len(aggregate.EvidenceBinding().Evidence[0].Reasons) != 0 {
		t.Fatal("trace mutation leaked into aggregate")
	}
	events := aggregate.DomainEvents()
	if len(events) != 2 || events[1].Metadata().EventType != "EvidenceSetBoundEvent" {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func TestEvidenceBindingSurvivesSnapshotRoundTrip(t *testing.T) {
	base := time.Now().UTC()
	sessionID := uuid.New()
	aggregate, _ := NewEvaluation(uuid.New(), sessionID, base)
	binding := testEvidenceBinding(sessionID, base)
	if err := aggregate.BindEvidenceSet(binding); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := aggregate.Snapshot()
	restored, err := RehydrateEvaluation(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if restored.EvidenceBinding() == nil || !evidenceBindingsEqual(*restored.EvidenceBinding(), binding) {
		t.Fatal("evidence binding changed during rehydration")
	}
}

func TestEvidenceMustBeBoundBeforeRuleOutcomes(t *testing.T) {
	base := time.Now().UTC()
	sessionID := uuid.New()
	aggregate, _ := NewEvaluation(uuid.New(), sessionID, base)
	_ = aggregate.RegisterRequiredRuleAt("weight", base)
	_ = aggregate.Start(base)
	_ = aggregate.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomePass, EvaluatedAt: base})
	if err := aggregate.BindEvidenceSet(testEvidenceBinding(sessionID, base)); !errors.Is(err, ErrEvidenceBoundAfterRules) {
		t.Fatalf("expected late binding error, got %v", err)
	}
}

func TestEvidenceBindingRejectsWrongSessionAndConflict(t *testing.T) {
	base := time.Now().UTC()
	sessionID := uuid.New()
	aggregate, _ := NewEvaluation(uuid.New(), sessionID, base)
	if err := aggregate.BindEvidenceSet(testEvidenceBinding(uuid.New(), base)); !errors.Is(err, ErrEvidenceSessionMismatch) {
		t.Fatalf("expected session error, got %v", err)
	}
	first := testEvidenceBinding(sessionID, base)
	if err := aggregate.BindEvidenceSet(first); err != nil {
		t.Fatal(err)
	}
	second := testEvidenceBinding(sessionID, base)
	if err := aggregate.BindEvidenceSet(second); !errors.Is(err, ErrEvidenceAlreadyBound) {
		t.Fatalf("expected binding conflict, got %v", err)
	}
}

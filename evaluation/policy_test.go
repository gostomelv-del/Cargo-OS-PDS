package evaluation

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

const testPolicyHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testPolicyBinding(at time.Time) PolicyBinding {
	return PolicyBinding{PolicyID: "cargo-transfer", Version: "1.2.0", Hash: testPolicyHash, BoundAt: at}
}

func TestVerificationPolicyBindingIsIdempotentAndTraced(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	aggregate, _ := NewEvaluation(uuid.New(), uuid.New(), base)
	binding := testPolicyBinding(base.Add(time.Second))
	if err := aggregate.BindVerificationPolicy(binding); err != nil {
		t.Fatal(err)
	}
	version := aggregate.Version()
	if err := aggregate.BindVerificationPolicy(binding); err != nil || aggregate.Version() != version {
		t.Fatalf("idempotent binding changed aggregate: %v", err)
	}
	trace, err := aggregate.DecisionTrace()
	if err != nil || trace.PolicyBinding == nil || trace.PolicyBinding.Hash != testPolicyHash {
		t.Fatalf("policy missing from trace: %#v, %v", trace, err)
	}
	events := aggregate.DomainEvents()
	if len(events) != 2 || events[1].Metadata().EventType != "VerificationPolicyBoundEvent" {
		t.Fatalf("unexpected policy events: %#v", events)
	}
}

func TestVerificationPolicySurvivesSnapshotRoundTrip(t *testing.T) {
	base := time.Now().UTC()
	aggregate, _ := NewEvaluation(uuid.New(), uuid.New(), base)
	binding := testPolicyBinding(base)
	_ = aggregate.BindVerificationPolicy(binding)
	snapshot, _ := aggregate.Snapshot()
	restored, err := RehydrateEvaluation(snapshot)
	if err != nil || restored.PolicyBinding() == nil || *restored.PolicyBinding() != binding {
		t.Fatalf("policy changed during rehydration: %#v, %v", restored.PolicyBinding(), err)
	}
}

func TestVerificationPolicyBindingFailsClosed(t *testing.T) {
	base := time.Now().UTC()
	aggregate, _ := NewEvaluation(uuid.New(), uuid.New(), base)
	invalid := testPolicyBinding(base)
	invalid.Hash = "sha256:not-a-hash"
	if err := aggregate.BindVerificationPolicy(invalid); !errors.Is(err, ErrPolicyBindingRequired) {
		t.Fatalf("expected hash validation error, got %v", err)
	}
	first := testPolicyBinding(base)
	if err := aggregate.BindVerificationPolicy(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Version = "1.2.1"
	if err := aggregate.BindVerificationPolicy(second); !errors.Is(err, ErrPolicyAlreadyBound) {
		t.Fatalf("expected policy conflict, got %v", err)
	}
}

func TestVerificationPolicyCannotBindAfterOutcomes(t *testing.T) {
	base := time.Now().UTC()
	aggregate, _ := NewEvaluation(uuid.New(), uuid.New(), base)
	_ = aggregate.RegisterRequiredRuleAt("weight", base)
	_ = aggregate.Start(base)
	_ = aggregate.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomePass, EvaluatedAt: base})
	if err := aggregate.BindVerificationPolicy(testPolicyBinding(base)); !errors.Is(err, ErrPolicyBoundAfterRules) {
		t.Fatalf("expected late policy error, got %v", err)
	}
}

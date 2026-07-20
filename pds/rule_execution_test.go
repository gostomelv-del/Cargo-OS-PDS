package pds

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
)

type testRuleOperator struct {
	id       string
	decision RuleDecision
	err      error
	called   int
	check    func(RuleInput) error
}

func (o *testRuleOperator) RuleID() string { return o.id }

func (o *testRuleOperator) Evaluate(_ context.Context, input RuleInput) (RuleDecision, error) {
	o.called++
	if o.check != nil {
		if err := o.check(input); err != nil {
			return RuleDecision{}, err
		}
	}
	return o.decision, o.err
}

type executionFixture struct {
	evaluations *Service
	evidence    *evidence.Service
	store       *MemoryStore
	evaluation  evaluation.EvaluationSnapshot
	qualified   evidence.SessionQualificationResult
	now         time.Time
}

const executionPolicyHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newExecutionFixture(t *testing.T, ruleIDs []string, policy evidence.QualificationPolicy) executionFixture {
	t.Helper()
	now := time.Date(2026, 7, 20, 16, 0, 0, 0, time.UTC)
	repository := evidence.NewMemoryRepository()
	evidenceService, err := evidence.NewService(repository, evidence.ServiceConfig{
		SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test",
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	accepted, err := evidenceService.Ingest(context.Background(), evidence.Input{
		SessionID: sessionID, SourceID: "scale-17", SourceType: "WEIGHT_SENSOR",
		EvidenceType: evidence.TypeWeight, ObservedAt: now.Add(-time.Second),
		Payload: json.RawMessage(`{"unit":"kg","value":25}`), AcquisitionMethod: "HTTP",
	})
	if err != nil || accepted.EvidenceID == uuid.Nil {
		t.Fatalf("failed to ingest fixture evidence: %v", err)
	}
	qualifier, err := evidence.NewQualifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := evidenceService.QualifySession(context.Background(), sessionID, qualifier)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	evaluationService := NewServiceWithStore(store, func() time.Time { return now })
	created, err := evaluationService.Create(context.Background(), sessionID, ruleIDs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = evaluationService.Start(context.Background(), created.EvaluationID); err != nil {
		t.Fatal(err)
	}
	if _, err = evaluationService.BindEvidenceQualification(context.Background(), created.EvaluationID, qualified); err != nil {
		t.Fatal(err)
	}
	if _, err = evaluationService.BindVerificationPolicy(context.Background(), created.EvaluationID, evaluation.PolicyBinding{
		PolicyID: "cargo-transfer", Version: "policy.v1", Hash: executionPolicyHash, BoundAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return executionFixture{evaluationService, evidenceService, store, created, qualified, now}
}

func TestRuleExecutionUsesBoundQualifiedEvidence(t *testing.T) {
	fixture := newExecutionFixture(t, []string{"weight"}, evidence.QualificationPolicy{Version: "qualification.v1"})
	operator := &testRuleOperator{id: "weight", decision: RuleDecision{Status: evaluation.RuleOutcomePass}}
	operator.check = func(input RuleInput) error {
		if input.EvaluationID != fixture.evaluation.EvaluationID || input.SessionID != fixture.qualified.SessionID ||
			input.PolicyID != "cargo-transfer" || input.PolicyVersion != "policy.v1" || input.PolicyHash != executionPolicyHash ||
			len(input.Evidence) != 1 ||
			input.Evidence[0].EvidenceID != fixture.qualified.Evidence[0].EvidenceID {
			return errors.New("wrong rule input")
		}
		input.Evidence[0].Payload[0] = '['
		return nil
	}
	runner, err := NewRuleExecutionService(fixture.evaluations, fixture.evidence, []RuleOperator{operator})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := runner.Execute(context.Background(), fixture.evaluation.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	if operator.called != 1 || len(snapshot.RuleOutcomes) != 1 || snapshot.RuleOutcomes[0].Status != evaluation.RuleOutcomePass {
		t.Fatalf("unexpected execution result: %#v", snapshot.RuleOutcomes)
	}
	if _, err = runner.Execute(context.Background(), fixture.evaluation.EvaluationID); err != nil || operator.called != 1 {
		t.Fatalf("completed execution retry was not idempotent: calls=%d, err=%v", operator.called, err)
	}
	found, err := fixture.evidence.Find(context.Background(), fixture.qualified.Evidence[0].EvidenceID)
	if err != nil || found.Payload[0] != '{' {
		t.Fatal("operator mutation leaked into stored evidence")
	}
	records := fixture.store.OutboxRecords()
	if records[len(records)-1].EventType != "RuleOutcomeBatchRecordedEvent" {
		t.Fatalf("atomic outcome event missing: %#v", records)
	}
}

func TestRuleExecutionFailsClosedForRejectedEvidence(t *testing.T) {
	fixture := newExecutionFixture(t, []string{"weight"}, evidence.QualificationPolicy{
		Version: "qualification.v1", TrustedSources: map[string]bool{"different-source": true},
	})
	operator := &testRuleOperator{id: "weight", decision: RuleDecision{Status: evaluation.RuleOutcomePass}}
	runner, _ := NewRuleExecutionService(fixture.evaluations, fixture.evidence, []RuleOperator{operator})
	if _, err := runner.Execute(context.Background(), fixture.evaluation.EvaluationID); !errors.Is(err, ErrEvidenceNotQualified) {
		t.Fatalf("expected qualification error, got %v", err)
	}
	if operator.called != 0 {
		t.Fatal("operator ran with rejected evidence")
	}
}

func TestRuleExecutionIsAtomicWhenOperatorFails(t *testing.T) {
	fixture := newExecutionFixture(t, []string{"first", "second"}, evidence.QualificationPolicy{Version: "qualification.v1"})
	first := &testRuleOperator{id: "first", decision: RuleDecision{Status: evaluation.RuleOutcomePass}}
	second := &testRuleOperator{id: "second", err: errors.New("operator unavailable")}
	runner, _ := NewRuleExecutionService(fixture.evaluations, fixture.evidence, []RuleOperator{first, second})
	if _, err := runner.Execute(context.Background(), fixture.evaluation.EvaluationID); !errors.Is(err, ErrRuleExecutionFailed) {
		t.Fatalf("expected execution error, got %v", err)
	}
	trace, err := fixture.evaluations.Trace(context.Background(), fixture.evaluation.EvaluationID)
	if err != nil || len(trace.RuleOutcomes) != 0 {
		t.Fatalf("partial outcomes were committed: %#v, %v", trace.RuleOutcomes, err)
	}
}

func TestRuleExecutionRequiresEveryOperator(t *testing.T) {
	fixture := newExecutionFixture(t, []string{"weight"}, evidence.QualificationPolicy{Version: "qualification.v1"})
	runner, _ := NewRuleExecutionService(fixture.evaluations, fixture.evidence, nil)
	if _, err := runner.Execute(context.Background(), fixture.evaluation.EvaluationID); !errors.Is(err, ErrRuleOperatorMissing) {
		t.Fatalf("expected missing operator error, got %v", err)
	}
}

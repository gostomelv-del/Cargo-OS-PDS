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
)

func sequenceEvidence(t *testing.T, id string, source, payload string, observedAt time.Time) evidence.Snapshot {
	t.Helper()
	evidenceID, err := uuid.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	object, err := evidence.NewObject(evidence.Input{
		EvidenceID: evidenceID, SessionID: uuid.New(), SourceID: source,
		SourceType: "CONTACT_SENSOR", EvidenceType: evidence.TypeContact,
		ObservedAt: observedAt, ReceivedAt: observedAt, Payload: json.RawMessage(payload),
		SchemaVersion: "evidence.v1", RuntimeVersion: "test", AcquisitionMethod: "TEST",
	})
	if err != nil {
		t.Fatal(err)
	}
	return object.Snapshot()
}

func supportSequence(t *testing.T, maxGap, maxDuration time.Duration) *SequenceOperator {
	t.Helper()
	operator, err := NewSequenceOperator("support-transfer", []SequenceStep{
		{Selector: Selector{EvidenceType: evidence.TypeContact, SourceID: "target", JSONPointer: "/confirmed"}, Expected: json.RawMessage(`true`)},
		{Selector: Selector{EvidenceType: evidence.TypeContact, SourceID: "source", JSONPointer: "/released"}, Expected: json.RawMessage(`true`)},
	}, maxGap, maxDuration)
	if err != nil {
		t.Fatal(err)
	}
	return operator
}

func TestSequenceOperatorSortsEvidenceAndAcceptsWindowBoundary(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	target := sequenceEvidence(t, "00000000-0000-0000-0000-000000000001", "target", `{"confirmed":true}`, base)
	source := sequenceEvidence(t, "00000000-0000-0000-0000-000000000002", "source", `{"released":true}`, base.Add(2*time.Second))
	decision, err := supportSequence(t, 2*time.Second, 2*time.Second).Evaluate(context.Background(), ruleInput(source, target))
	if err != nil || decision.Status != evaluation.RuleOutcomePass {
		t.Fatalf("expected sequence pass, got %#v, %v", decision, err)
	}
}

func TestSequenceOperatorUsesEvidenceIDForEqualTimestamps(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	target := sequenceEvidence(t, "00000000-0000-0000-0000-000000000001", "target", `{"confirmed":true}`, base)
	source := sequenceEvidence(t, "00000000-0000-0000-0000-000000000002", "source", `{"released":true}`, base)
	decision, _ := supportSequence(t, 0, 0).Evaluate(context.Background(), ruleInput(source, target))
	if decision.Status != evaluation.RuleOutcomePass {
		t.Fatalf("Evidence-ID tie break was not deterministic: %#v", decision)
	}
}

func TestSequenceOperatorRejectsWrongOrder(t *testing.T) {
	base := time.Now().UTC()
	source := sequenceEvidence(t, "00000000-0000-0000-0000-000000000001", "source", `{"released":true}`, base)
	target := sequenceEvidence(t, "00000000-0000-0000-0000-000000000002", "target", `{"confirmed":true}`, base.Add(time.Second))
	decision, _ := supportSequence(t, 2*time.Second, 0).Evaluate(context.Background(), ruleInput(target, source))
	if decision.Status != evaluation.RuleOutcomeFail || decision.ReasonCodes[0] != reasonSequenceOrderInvalid {
		t.Fatalf("wrong order did not fail: %#v", decision)
	}
}

func TestSequenceOperatorReportsMissingStepInconclusive(t *testing.T) {
	base := time.Now().UTC()
	target := sequenceEvidence(t, "00000000-0000-0000-0000-000000000001", "target", `{"confirmed":true}`, base)
	decision, _ := supportSequence(t, 0, 0).Evaluate(context.Background(), ruleInput(target))
	if decision.Status != evaluation.RuleOutcomeInconclusive || decision.ReasonCodes[0] != reasonSequenceIncomplete {
		t.Fatalf("missing step was not inconclusive: %#v", decision)
	}
}

func TestSequenceOperatorEnforcesGapAndValue(t *testing.T) {
	base := time.Now().UTC()
	target := sequenceEvidence(t, "00000000-0000-0000-0000-000000000001", "target", `{"confirmed":true}`, base)
	late := sequenceEvidence(t, "00000000-0000-0000-0000-000000000002", "source", `{"released":true}`, base.Add(2001*time.Millisecond))
	decision, _ := supportSequence(t, 2*time.Second, 0).Evaluate(context.Background(), ruleInput(target, late))
	if decision.Status != evaluation.RuleOutcomeFail || decision.ReasonCodes[0] != reasonSequenceGapExceeded {
		t.Fatalf("excessive gap did not fail: %#v", decision)
	}
	wrong := sequenceEvidence(t, "00000000-0000-0000-0000-000000000003", "source", `{"released":false}`, base.Add(time.Second))
	decision, _ = supportSequence(t, 2*time.Second, 0).Evaluate(context.Background(), ruleInput(target, wrong))
	if decision.Status != evaluation.RuleOutcomeFail || decision.ReasonCodes[0] != reasonSequenceValueMismatch {
		t.Fatalf("wrong step value did not fail: %#v", decision)
	}
}

func TestSequenceOperatorEnforcesTotalDuration(t *testing.T) {
	base := time.Now().UTC()
	operator, err := NewSequenceOperator("three-step", []SequenceStep{
		{Selector: Selector{EvidenceType: evidence.TypeContact, SourceID: "one", JSONPointer: "/ok"}, Expected: json.RawMessage(`true`)},
		{Selector: Selector{EvidenceType: evidence.TypeContact, SourceID: "two", JSONPointer: "/ok"}, Expected: json.RawMessage(`true`)},
		{Selector: Selector{EvidenceType: evidence.TypeContact, SourceID: "three", JSONPointer: "/ok"}, Expected: json.RawMessage(`true`)},
	}, 2*time.Second, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	input := ruleInput(
		sequenceEvidence(t, "00000000-0000-0000-0000-000000000001", "one", `{"ok":true}`, base),
		sequenceEvidence(t, "00000000-0000-0000-0000-000000000002", "two", `{"ok":true}`, base.Add(2*time.Second)),
		sequenceEvidence(t, "00000000-0000-0000-0000-000000000003", "three", `{"ok":true}`, base.Add(4*time.Second)),
	)
	decision, _ := operator.Evaluate(context.Background(), input)
	if decision.Status != evaluation.RuleOutcomeFail || decision.ReasonCodes[0] != reasonSequenceDurationExceeded {
		t.Fatalf("total duration did not fail: %#v", decision)
	}
}

func TestSequenceConfigurationValidation(t *testing.T) {
	step := SequenceStep{Selector: Selector{EvidenceType: evidence.TypeContact}, Expected: json.RawMessage(`true`)}
	if _, err := NewSequenceOperator("sequence", []SequenceStep{step}, 0, 0); !errors.Is(err, ErrSequenceStepsRequired) {
		t.Fatalf("expected steps error, got %v", err)
	}
	if _, err := NewSequenceOperator("sequence", []SequenceStep{step, step}, -time.Second, 0); !errors.Is(err, ErrInvalidSequenceWindow) {
		t.Fatalf("expected window error, got %v", err)
	}
}

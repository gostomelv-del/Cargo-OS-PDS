package evidencebundle

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"cargoos/evaluation"
	"cargoos/policy"
)

func independentlyVerifiableBundle(t *testing.T) Bundle {
	t.Helper()
	input, _ := policySnapshotFixture(t)
	version, err := policy.NewVersion(policy.Input{
		PolicyID: "cargo-transfer", Version: "1.0.0", SchemaVersion: "policy.document.v1",
		EffectiveFrom:   input.Trace.CreatedAt,
		RequiredRuleIDs: []string{"weight"},
		Document:        json.RawMessage(`{"evidence_qualification":{"version":"qualification.v1","trusted_sources":["scale-17"],"allowed_types":["WEIGHT"],"allowed_acquisition_methods":["HTTP"]},"rules":[{"rule_id":"weight","operator":"RANGE","selector":{"evidence_type":"WEIGHT","json_pointer":"/value"},"minimum":"0","maximum":"25"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := version.Snapshot()
	input.Trace.PolicyBinding.Hash = snapshot.Hash
	bundle, err := BuildWithPolicySnapshot(input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestVerifyDecisionRecalculatesExactOutcomeAndResult(t *testing.T) {
	bundle := independentlyVerifiableBundle(t)
	report, err := VerifyDecision(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified || report.StoredResult != evaluation.ResultVerified ||
		report.RecalculatedResult != evaluation.ResultVerified || len(report.Outcomes) != 1 ||
		report.Outcomes[0].RuleID != "weight" || report.Outcomes[0].Status != evaluation.RuleOutcomePass {
		t.Fatalf("unexpected independent verification report: %#v", report)
	}
}

func TestVerifyDecisionRejectsRecalculatedOutcomeMismatch(t *testing.T) {
	bundle := independentlyVerifiableBundle(t)
	for objectIndex := range bundle.Objects {
		if bundle.Objects[objectIndex].Path != "decision-trace.json" {
			continue
		}
		var trace evaluation.DecisionTrace
		if err := json.Unmarshal(bundle.Objects[objectIndex].Payload, &trace); err != nil {
			t.Fatal(err)
		}
		trace.RuleOutcomes[0].Status = evaluation.RuleOutcomeFail
		trace.Result = evaluation.ResultRejected
		bundle.Objects[objectIndex].Payload, _ = json.Marshal(trace)
		bundle.Manifest.Objects[objectIndex] = describe(bundle.Objects[objectIndex])
		bundle.Manifest.BundleRoot = calculateRoot(bundle.Manifest)
		break
	}
	if _, err := VerifyDecision(context.Background(), bundle); !errors.Is(err, ErrRecalculatedOutcomeMismatch) {
		t.Fatalf("expected independent outcome mismatch, got %v", err)
	}
}

func TestVerifyDecisionRejectsRecalculatedResultMismatch(t *testing.T) {
	bundle := independentlyVerifiableBundle(t)
	for objectIndex := range bundle.Objects {
		if bundle.Objects[objectIndex].Path != "decision-trace.json" {
			continue
		}
		var trace evaluation.DecisionTrace
		if err := json.Unmarshal(bundle.Objects[objectIndex].Payload, &trace); err != nil {
			t.Fatal(err)
		}
		trace.Result = evaluation.ResultManualReview
		bundle.Objects[objectIndex].Payload, _ = json.Marshal(trace)
		bundle.Manifest.Objects[objectIndex] = describe(bundle.Objects[objectIndex])
		bundle.Manifest.BundleRoot = calculateRoot(bundle.Manifest)
		break
	}
	if _, err := VerifyDecision(context.Background(), bundle); !errors.Is(err, ErrRecalculatedDecisionMismatch) {
		t.Fatalf("expected independent decision mismatch, got %v", err)
	}
}

func TestVerifyDecisionRequiresCompletePolicySnapshot(t *testing.T) {
	input := bundleFixture(t)
	bundle, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyDecision(context.Background(), bundle); !errors.Is(err, ErrPolicySnapshotRequired) {
		t.Fatalf("expected complete Policy Snapshot requirement, got %v", err)
	}
}

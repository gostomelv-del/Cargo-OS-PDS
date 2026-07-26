package evidencebundle

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
)

const bundlePolicyHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func bundleFixture(t *testing.T) BuildInput {
	t.Helper()
	base := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.New()
	evidenceID := uuid.New()
	object, err := evidence.NewObject(evidence.Input{
		EvidenceID: evidenceID, SessionID: sessionID,
		SourceID: "scale-17", SourceType: "WEIGHT_SENSOR",
		EvidenceType: evidence.TypeWeight,
		ObservedAt:   base, ReceivedAt: base.Add(time.Second),
		Payload:       json.RawMessage(`{"unit":"kg","value":25}`),
		SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test",
		AcquisitionMethod: "HTTP",
	})
	if err != nil {
		t.Fatal(err)
	}
	trace := evaluation.DecisionTrace{
		EvaluationID: uuid.New(), SessionID: sessionID, Version: 8,
		State: evaluation.StateCompleted, Result: evaluation.ResultVerified,
		RequiredRuleIDs: []string{"weight"},
		RuleOutcomes: []evaluation.RuleOutcome{{
			RuleID: "weight", Status: evaluation.RuleOutcomePass,
			EvaluatedAt: base.Add(2 * time.Second),
		}},
		CreatedAt: base, StartedAt: timePointer(base.Add(time.Second)),
		CompletedAt: timePointer(base.Add(3 * time.Second)),
		EvidenceBinding: &evaluation.EvidenceSetBinding{
			SessionID: sessionID, Status: evaluation.EvidenceQualified,
			PolicyVersion: "qualification.v1", QualifiedAt: base.Add(2 * time.Second),
			Evidence: []evaluation.EvidenceReference{{
				EvidenceID: evidenceID, Status: evaluation.EvidenceQualified,
			}},
		},
		PolicyBinding: &evaluation.PolicyBinding{
			PolicyID: "cargo-transfer", Version: "1.0.0",
			Hash: bundlePolicyHash, BoundAt: base,
		},
	}
	return BuildInput{
		BundleID: uuid.New(), GeneratedAt: base.Add(4 * time.Second),
		Trace: trace, Evidence: []evidence.Snapshot{object.Snapshot()},
	}
}

func TestBuildProducesDeterministicVerifiableManifest(t *testing.T) {
	input := bundleFixture(t)
	first, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := CanonicalManifest(first.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := CanonicalManifest(second.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) ||
		first.Manifest.BundleRoot != second.Manifest.BundleRoot {
		t.Fatalf("bundle manifest is not deterministic:\n%s\n%s", firstJSON, secondJSON)
	}
	if len(first.Manifest.Objects) != 3 ||
		first.Manifest.Objects[0].Path != "decision-trace.json" ||
		first.Manifest.Objects[1].Path[:9] != "evidence/" ||
		first.Manifest.Objects[2].Path != "policy/reference.json" {
		t.Fatalf("unexpected object order: %#v", first.Manifest.Objects)
	}
	if err = Verify(first); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDetectsObjectModification(t *testing.T) {
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	bundle.Objects[0].Payload[0] = '['
	if err = Verify(bundle); !errors.Is(err, ErrObjectDigestMismatch) {
		t.Fatalf("expected object modification detection, got %v", err)
	}
}

func TestVerifyDetectsManifestModification(t *testing.T) {
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	bundle.Manifest.Policy.Version = "substituted"
	if err = Verify(bundle); !errors.Is(err, ErrBundleRootMismatch) {
		t.Fatalf("expected manifest modification detection, got %v", err)
	}
}

func TestBuildRejectsMissingOrSubstitutedEvidence(t *testing.T) {
	input := bundleFixture(t)
	input.Evidence = nil
	if _, err := Build(input); !errors.Is(err, ErrEvidenceObjectMismatch) {
		t.Fatalf("expected missing Evidence rejection, got %v", err)
	}
	input = bundleFixture(t)
	input.Evidence[0].EvidenceID = uuid.New()
	if _, err := Build(input); err == nil {
		t.Fatal("expected substituted Evidence rejection")
	}
}

func TestBuildRequiresFinalizedTraceAndGenerationTime(t *testing.T) {
	input := bundleFixture(t)
	input.Trace.State = evaluation.StateRunning
	input.Trace.CompletedAt = nil
	if _, err := Build(input); !errors.Is(err, ErrFinalDecisionRequired) {
		t.Fatalf("expected non-terminal trace rejection, got %v", err)
	}
	input = bundleFixture(t)
	input.GeneratedAt = input.Trace.CompletedAt.Add(-time.Nanosecond)
	if _, err := Build(input); !errors.Is(err, ErrFinalDecisionRequired) {
		t.Fatalf("expected pre-completion generation rejection, got %v", err)
	}
}

func TestBundleObjectsAreDefensiveCopies(t *testing.T) {
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	original := bundle.Manifest.Objects[0].Digest
	bundle.Objects[0].Payload[0] = '['
	if bundle.Manifest.Objects[0].Digest != original {
		t.Fatal("object mutation changed manifest")
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}

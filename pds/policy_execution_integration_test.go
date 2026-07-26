package pds_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
	"cargoos/policy"
	"cargoos/ruleoperator"
)

func TestSignedPolicyExecutesBoundRuleEndToEnd(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	registry := policy.NewRegistry()
	version := admitRangePolicy(t, ctx, registry, now)

	evidenceService, err := evidence.NewService(
		evidence.NewMemoryRepository(),
		evidence.ServiceConfig{
			SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test",
			Clock: func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	accepted, err := evidenceService.Ingest(ctx, evidence.Input{
		SessionID: sessionID, SourceID: "scale-17", SourceType: "WEIGHT_SENSOR",
		EvidenceType: evidence.TypeWeight, ObservedAt: now.Add(-time.Second),
		Payload: json.RawMessage(`{"unit":"kg","value":25}`), AcquisitionMethod: "HTTP",
	})
	if err != nil {
		t.Fatal(err)
	}
	qualifier, err := evidence.NewQualifier(evidence.QualificationPolicy{
		Version:        "qualification.v1",
		TrustedSources: map[string]bool{"scale-17": true},
		AllowedTypes:   map[evidence.Type]bool{evidence.TypeWeight: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := evidenceService.QualifySession(ctx, sessionID, qualifier)
	if err != nil {
		t.Fatal(err)
	}

	store := pds.NewMemoryStore()
	evaluationService := pds.NewServiceWithStore(store, func() time.Time { return now })
	created, err := evaluationService.CreateForPolicy(ctx, sessionID, "cargo-transfer", registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = evaluationService.Start(ctx, created.EvaluationID); err != nil {
		t.Fatal(err)
	}
	if _, err = evaluationService.BindEvidenceQualification(ctx, created.EvaluationID, qualified); err != nil {
		t.Fatal(err)
	}
	resolver, err := pds.NewPolicyDocumentRuleResolver(
		registry,
		ruleoperator.PolicyDocumentCompiler{},
	)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := pds.NewRuleExecutionServiceWithResolver(
		evaluationService,
		evidenceService,
		resolver,
	)
	if err != nil {
		t.Fatal(err)
	}
	executed, err := executor.Execute(ctx, created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(executed.RuleOutcomes) != 1 ||
		executed.RuleOutcomes[0].RuleID != "weight-range" ||
		executed.RuleOutcomes[0].Status != evaluation.RuleOutcomePass {
		t.Fatalf("unexpected Rule Outcomes: %#v", executed.RuleOutcomes)
	}

	trace, err := evaluationService.Complete(ctx, created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := version.Snapshot()
	if trace.State != evaluation.StateCompleted ||
		trace.Result != evaluation.ResultVerified ||
		trace.PolicyBinding == nil ||
		trace.PolicyBinding.PolicyID != snapshot.PolicyID ||
		trace.PolicyBinding.Version != snapshot.Version ||
		trace.PolicyBinding.Hash != snapshot.Hash ||
		trace.EvidenceBinding == nil ||
		len(trace.EvidenceBinding.Evidence) != 1 ||
		trace.EvidenceBinding.Evidence[0].EvidenceID != accepted.EvidenceID {
		t.Fatalf("incomplete end-to-end Decision Trace: %#v", trace)
	}
	records := store.OutboxRecords()
	if len(records) == 0 || records[len(records)-1].EventType != "EvaluationCompletedEvent" {
		t.Fatalf("completion was not persisted through the outbox: %#v", records)
	}
}

func admitRangePolicy(
	t *testing.T,
	ctx context.Context,
	registry *policy.Registry,
	at time.Time,
) *policy.Version {
	t.Helper()
	version, err := policy.NewVersion(policy.Input{
		PolicyID: "cargo-transfer", Version: "1.0.0",
		SchemaVersion:   ruleoperator.PolicyDocumentSchemaV1,
		EffectiveFrom:   at.Add(-time.Hour),
		RequiredRuleIDs: []string{"weight-range"},
		Document: json.RawMessage(`{"rules":[{
			"rule_id":"weight-range",
			"operator":"RANGE",
			"selector":{"evidence_type":"WEIGHT","source_id":"scale-17","json_pointer":"/value"},
			"minimum":"20",
			"maximum":"30"
		}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	trustStore, err := policy.NewMemoryTrustStore(policy.VerificationKey{
		SignerID: "policy-authority", KeyID: "key-1",
		Algorithm: policy.AlgorithmEd25519,
		PublicKey: privateKey.Public().(ed25519.PublicKey),
		ValidFrom: at.Add(-2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := policy.NewVerifier(trustStore)
	if err != nil {
		t.Fatal(err)
	}
	signature := policy.Signature{
		SignerID: "policy-authority", KeyID: "key-1",
		Algorithm: policy.AlgorithmEd25519, SignedAt: at.Add(-time.Minute),
	}
	payload, err := policy.SigningPayload(version, signature)
	if err != nil {
		t.Fatal(err)
	}
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	snapshot := version.Snapshot()
	admission, err := policy.NewAdmissionService(
		verifier,
		ruleoperator.PolicyDocumentCompiler{},
		registry,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admission.Admit(ctx, version, signature, policy.ApprovalRecord{
		PolicyID: snapshot.PolicyID, Version: snapshot.Version, PolicyHash: snapshot.Hash,
		ApprovedBy: "policy-review-board", ApprovedAt: at.Add(-time.Second),
	}, at, at); err != nil {
		t.Fatal(err)
	}
	return version
}

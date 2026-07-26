package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
	"cargoos/policy"
	"cargoos/ruleoperator"
)

func TestSignedPolicyExecutionThroughHTTP(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 26, 14, 0, 0, 0, time.UTC)
	registry := policy.NewRegistry()
	version := admitHTTPRangePolicy(t, ctx, registry, now)

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
	evaluationService := pds.NewService(func() time.Time { return now })
	qualificationService, err := pds.NewPolicyEvidenceQualificationService(
		evaluationService,
		evidenceService,
		registry,
		ruleoperator.PolicyDocumentCompiler{},
	)
	if err != nil {
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
	handler := NewHandlerWithQualificationRuntime(
		evaluationService,
		evidenceService,
		registry,
		qualificationService,
		executor,
		nil,
	)

	sessionID := uuid.New()
	evidenceID := uuid.New()
	evidenceBody := fmt.Sprintf(`{
		"evidence_id":%q,
		"session_id":%q,
		"source_id":"scale-17",
		"source_type":"WEIGHT_SENSOR",
		"evidence_type":"WEIGHT",
		"observed_at":"2026-07-26T13:59:59Z",
		"payload":{"unit":"kg","value":25}
	}`, evidenceID.String(), sessionID.String())
	perform(t, handler, http.MethodPost, "/v1/evidence", evidenceBody, http.StatusCreated)

	createdResponse := perform(t, handler, http.MethodPost, "/v1/evaluations",
		fmt.Sprintf(`{"session_id":%q,"policy_id":"cargo-transfer"}`, sessionID.String()),
		http.StatusCreated)
	var created evaluation.EvaluationSnapshot
	if err = json.Unmarshal(createdResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	basePath := "/v1/evaluations/" + created.EvaluationID.String()
	perform(t, handler, http.MethodPost, basePath+"/start", "", http.StatusOK)
	qualifiedResponse := perform(t, handler, http.MethodPost,
		basePath+"/qualify-evidence", "", http.StatusOK)
	var qualified evaluation.EvaluationSnapshot
	if err = json.Unmarshal(qualifiedResponse.Body.Bytes(), &qualified); err != nil {
		t.Fatal(err)
	}
	if qualified.EvidenceBinding == nil ||
		qualified.EvidenceBinding.Status != evaluation.EvidenceQualified {
		t.Fatalf("Evidence was not qualified from Policy: %#v", qualified.EvidenceBinding)
	}
	executedResponse := perform(t, handler, http.MethodPost,
		basePath+"/execute-rules", "", http.StatusOK)
	var executed evaluation.EvaluationSnapshot
	if err = json.Unmarshal(executedResponse.Body.Bytes(), &executed); err != nil {
		t.Fatal(err)
	}
	if len(executed.RuleOutcomes) != 1 ||
		executed.RuleOutcomes[0].Status != evaluation.RuleOutcomePass {
		t.Fatalf("unexpected Rule Outcomes: %#v", executed.RuleOutcomes)
	}
	perform(t, handler, http.MethodPost, basePath+"/complete", "", http.StatusOK)
	traceResponse := perform(t, handler, http.MethodGet,
		basePath+"/decision-trace", "", http.StatusOK)
	var trace evaluation.DecisionTrace
	if err = json.Unmarshal(traceResponse.Body.Bytes(), &trace); err != nil {
		t.Fatal(err)
	}
	policySnapshot := version.Snapshot()
	if trace.Result != evaluation.ResultVerified ||
		trace.PolicyBinding == nil ||
		trace.PolicyBinding.Hash != policySnapshot.Hash ||
		trace.EvidenceBinding == nil ||
		len(trace.EvidenceBinding.Evidence) != 1 ||
		trace.EvidenceBinding.Evidence[0].EvidenceID != evidenceID {
		t.Fatalf("incomplete HTTP Decision Trace: %#v", trace)
	}
}

func admitHTTPRangePolicy(
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
		Document: json.RawMessage(`{
			"evidence_qualification":{
				"version":"qualification.v1",
				"trusted_sources":["scale-17"],
				"allowed_types":["WEIGHT"],
				"allowed_acquisition_methods":["HTTP"]
			},
			"rules":[{
				"rule_id":"weight-range",
				"operator":"RANGE",
				"selector":{
					"evidence_type":"WEIGHT",
					"source_id":"scale-17",
					"json_pointer":"/value"
				},
				"minimum":"20",
				"maximum":"30"
			}]
		}`),
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
		PolicyID: snapshot.PolicyID, Version: snapshot.Version,
		PolicyHash: snapshot.Hash, ApprovedBy: "policy-review-board",
		ApprovedAt: at.Add(-time.Second),
	}, at, at); err != nil {
		t.Fatal(err)
	}
	return version
}

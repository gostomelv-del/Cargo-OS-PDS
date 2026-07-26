package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
	"cargoos/policy"
)

type staticPolicyResolver struct {
	version *policy.Version
}

type recordingRuleExecutor struct {
	calledWith uuid.UUID
	snapshot   evaluation.EvaluationSnapshot
	err        error
}

func (e *recordingRuleExecutor) Execute(_ context.Context, id uuid.UUID) (evaluation.EvaluationSnapshot, error) {
	e.calledWith = id
	return e.snapshot, e.err
}

func (r staticPolicyResolver) Resolve(_ context.Context, policyID string, at time.Time) (*policy.Version, error) {
	if r.version == nil || r.version.Snapshot().PolicyID != policyID || !r.version.IsEffectiveAt(at) {
		return nil, policy.ErrPolicyNotFound
	}
	return r.version, nil
}

func evaluationHandler(t *testing.T, service *pds.Service, from time.Time, rules []string) http.Handler {
	t.Helper()
	version, err := policy.NewVersion(policy.Input{
		PolicyID: "cargo-transfer", Version: "1.0.0", SchemaVersion: "policy.v1",
		EffectiveFrom: from, RequiredRuleIDs: rules, Document: json.RawMessage(`{"mode":"strict"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewHandlerWithPolicyResolver(service, nil, staticPolicyResolver{version: version}, nil)
}

func TestEvaluationDecisionTraceFlow(t *testing.T) {
	now := time.Date(2026, 7, 20, 14, 0, 0, 0, time.UTC)
	service := pds.NewService(func() time.Time {
		now = now.Add(time.Second)
		return now
	})
	handler := evaluationHandler(t, service, now.Add(-time.Hour), []string{"weight"})

	created := perform(t, handler, http.MethodPost, "/v1/evaluations",
		`{"policy_id":"cargo-transfer"}`, http.StatusCreated)
	var snapshot evaluation.EvaluationSnapshot
	if err := json.Unmarshal(created.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	id := snapshot.EvaluationID.String()

	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/start", "", http.StatusOK)
	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/outcomes",
		`{"rule_id":"weight","status":"PASS"}`, http.StatusNotFound)
	if _, err := service.RecordOutcome(context.Background(), snapshot.EvaluationID, evaluation.RuleOutcome{
		RuleID: "weight", Status: evaluation.RuleOutcomePass,
	}); err != nil {
		t.Fatal(err)
	}
	completed := perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/complete", "", http.StatusOK)

	var trace evaluation.DecisionTrace
	if err := json.Unmarshal(completed.Body.Bytes(), &trace); err != nil {
		t.Fatal(err)
	}
	if trace.Result != evaluation.ResultVerified || len(trace.MissingRuleIDs) != 0 {
		t.Fatalf("unexpected trace: %#v", trace)
	}

	perform(t, handler, http.MethodGet, "/v1/evaluations/"+id+"/decision-trace", "", http.StatusOK)
}

func TestManualOutcomeInjectionDoesNotChangeEvaluation(t *testing.T) {
	now := time.Date(2026, 7, 26, 11, 0, 0, 0, time.UTC)
	service := pds.NewService(func() time.Time {
		now = now.Add(time.Second)
		return now
	})
	handler := evaluationHandler(t, service, now.Add(-time.Hour), []string{"weight"})
	created := perform(t, handler, http.MethodPost, "/v1/evaluations",
		`{"policy_id":"cargo-transfer"}`, http.StatusCreated)
	var snapshot evaluation.EvaluationSnapshot
	if err := json.Unmarshal(created.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	id := snapshot.EvaluationID.String()
	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/start", "", http.StatusOK)
	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/outcomes",
		`{"rule_id":"weight","status":"PASS"}`, http.StatusNotFound)
	trace := perform(t, handler, http.MethodGet, "/v1/evaluations/"+id+"/decision-trace", "", http.StatusOK)
	var decision evaluation.DecisionTrace
	if err := json.Unmarshal(trace.Body.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if len(decision.RuleOutcomes) != 0 || len(decision.MissingRuleIDs) != 1 || decision.MissingRuleIDs[0] != "weight" {
		t.Fatalf("manual outcome injection changed the evaluation: %#v", decision)
	}
}

func TestRuleExecutionEndpointDelegatesWithoutCallerOutcomes(t *testing.T) {
	evaluationID := uuid.New()
	executor := &recordingRuleExecutor{snapshot: evaluation.EvaluationSnapshot{EvaluationID: evaluationID}}
	handler := NewHandlerWithRuntime(pds.NewService(nil), nil, nil, executor, nil)
	perform(t, handler, http.MethodPost,
		"/v1/evaluations/"+evaluationID.String()+"/execute-rules",
		`{"rule_id":"injected","status":"PASS"}`,
		http.StatusBadRequest,
	)
	if executor.calledWith != uuid.Nil {
		t.Fatalf("caller-defined outcome reached executor: %s", executor.calledWith)
	}
	response := perform(t, handler, http.MethodPost,
		"/v1/evaluations/"+evaluationID.String()+"/execute-rules", "", http.StatusOK)
	if executor.calledWith != evaluationID {
		t.Fatalf("executor received %s, want %s", executor.calledWith, evaluationID)
	}
	var snapshot evaluation.EvaluationSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.EvaluationID != evaluationID {
		t.Fatalf("unexpected execution response: %#v", snapshot)
	}
}

func TestRuleExecutionEndpointFailsClosedWithoutExecutor(t *testing.T) {
	id := uuid.New().String()
	perform(t, NewHandler(pds.NewService(nil)), http.MethodPost,
		"/v1/evaluations/"+id+"/execute-rules", "", http.StatusServiceUnavailable)
}

func TestCompletionRejectsMissingRequiredRule(t *testing.T) {
	now := time.Now().UTC()
	service := pds.NewService(func() time.Time {
		now = now.Add(time.Second)
		return now
	})
	handler := evaluationHandler(t, service, now.Add(-time.Hour), []string{"weight"})
	created := perform(t, handler, http.MethodPost, "/v1/evaluations",
		`{"policy_id":"cargo-transfer"}`, http.StatusCreated)
	var snapshot evaluation.EvaluationSnapshot
	_ = json.Unmarshal(created.Body.Bytes(), &snapshot)
	id := snapshot.EvaluationID.String()
	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/start", "", http.StatusOK)
	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/complete", "", http.StatusConflict)
}

func TestEvaluationCreationRejectsClientSelectedRules(t *testing.T) {
	now := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	handler := evaluationHandler(t, pds.NewService(func() time.Time { return now }), now.Add(-time.Hour), []string{"policy-rule"})
	perform(t, handler, http.MethodPost, "/v1/evaluations",
		`{"policy_id":"cargo-transfer","required_rule_ids":["client-rule"]}`, http.StatusBadRequest)
	created := perform(t, handler, http.MethodPost, "/v1/evaluations",
		`{"policy_id":"cargo-transfer"}`, http.StatusCreated)
	var snapshot evaluation.EvaluationSnapshot
	if err := json.Unmarshal(created.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.RequiredRuleIDs) != 1 || snapshot.RequiredRuleIDs[0] != "policy-rule" || snapshot.PolicyBinding == nil {
		t.Fatalf("evaluation was not derived from policy: %#v", snapshot)
	}
}

func TestCommandsRejectTrailingJSONValues(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	handler := evaluationHandler(
		t,
		pds.NewService(func() time.Time { return now }),
		now.Add(-time.Hour),
		[]string{"weight"},
	)
	perform(t, handler, http.MethodPost, "/v1/evaluations",
		`{"policy_id":"cargo-transfer"}{"policy_id":"substitute"}`,
		http.StatusBadRequest,
	)

	executor := &recordingRuleExecutor{}
	runtimeHandler := NewHandlerWithRuntime(pds.NewService(nil), nil, nil, executor, nil)
	perform(t, runtimeHandler, http.MethodPost,
		"/v1/evaluations/"+uuid.New().String()+"/execute-rules",
		`{}{}`,
		http.StatusBadRequest,
	)
	if executor.calledWith != uuid.Nil {
		t.Fatalf("trailing JSON reached executor: %s", executor.calledWith)
	}
}

func TestCommandsRejectOversizedBodies(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 30, 0, 0, time.UTC)
	handler := evaluationHandler(
		t,
		pds.NewService(func() time.Time { return now }),
		now.Add(-time.Hour),
		[]string{"weight"},
	)
	body := `{"policy_id":"cargo-transfer"}` +
		strings.Repeat(" ", int(maxRequestBodyBytes))
	response := perform(t, handler, http.MethodPost, "/v1/evaluations",
		body, http.StatusRequestEntityTooLarge)
	if response.Body.String() != "{\"error\":\"request_body_too_large\"}\n" {
		t.Fatalf("unexpected oversized-body response: %s", response.Body.String())
	}
}

func TestHealth(t *testing.T) {
	perform(t, NewHandler(pds.NewService(nil)), http.MethodGet, "/healthz", "", http.StatusOK)
}

func TestReadiness(t *testing.T) {
	service := pds.NewService(nil)
	perform(t, NewHandlerWithReadiness(service, ReadinessFunc(func(context.Context) error {
		return nil
	})), http.MethodGet, "/readyz", "", http.StatusOK)
	perform(t, NewHandlerWithReadiness(service, ReadinessFunc(func(context.Context) error {
		return errors.New("database unavailable")
	})), http.MethodGet, "/readyz", "", http.StatusServiceUnavailable)
}

func TestEvidenceIngestRetrieveAndConflict(t *testing.T) {
	now := time.Date(2026, 7, 20, 15, 0, 0, 0, time.UTC)
	evidenceService, err := evidence.NewService(evidence.NewMemoryRepository(), evidence.ServiceConfig{
		SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test",
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandlerWithEvidence(pds.NewService(nil), evidenceService, nil)
	evidenceID := uuid.New()
	sessionID := uuid.New()
	body := fmt.Sprintf(`{
		"evidence_id":%q,"session_id":%q,"source_id":"scale-17",
		"source_type":"WEIGHT_SENSOR","evidence_type":"WEIGHT",
		"observed_at":"2026-07-20T14:59:59Z","payload":{"value":25,"unit":"kg"}
	}`, evidenceID.String(), sessionID.String())
	created := perform(t, handler, http.MethodPost, "/v1/evidence", body, http.StatusCreated)
	var accepted evidence.Snapshot
	if err = json.Unmarshal(created.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.EvidenceID != evidenceID || !accepted.ReceivedAt.Equal(now) {
		t.Fatalf("unexpected accepted evidence: %#v", accepted)
	}
	perform(t, handler, http.MethodPost, "/v1/evidence", body, http.StatusCreated)
	get := perform(t, handler, http.MethodGet, "/v1/evidence/"+evidenceID.String(), "", http.StatusOK)
	var retrieved evidence.Snapshot
	if err = json.Unmarshal(get.Body.Bytes(), &retrieved); err != nil {
		t.Fatal(err)
	}
	if retrieved.Integrity.PayloadDigest != accepted.Integrity.PayloadDigest {
		t.Fatal("retrieved evidence digest changed")
	}
	listed := perform(t, handler, http.MethodGet, "/v1/sessions/"+sessionID.String()+"/evidence", "", http.StatusOK)
	var evidenceSet []evidence.Snapshot
	if err = json.Unmarshal(listed.Body.Bytes(), &evidenceSet); err != nil {
		t.Fatal(err)
	}
	if len(evidenceSet) != 1 || evidenceSet[0].EvidenceID != evidenceID {
		t.Fatalf("unexpected session evidence set: %#v", evidenceSet)
	}
	conflict := strings.Replace(body, `"value":25`, `"value":26`, 1)
	perform(t, handler, http.MethodPost, "/v1/evidence", conflict, http.StatusConflict)
}

func TestEvidenceValidationAndNotFound(t *testing.T) {
	handler := NewHandler(pds.NewService(nil))
	perform(t, handler, http.MethodPost, "/v1/evidence", `{}`, http.StatusBadRequest)
	perform(t, handler, http.MethodGet, "/v1/evidence/not-a-uuid", "", http.StatusBadRequest)
	perform(t, handler, http.MethodGet, "/v1/evidence/"+uuid.New().String(), "", http.StatusNotFound)
	perform(t, handler, http.MethodGet, "/v1/sessions/not-a-uuid/evidence", "", http.StatusBadRequest)
}

func TestServiceErrorMapping(t *testing.T) {
	secret := errors.New("database password=do-not-expose")
	tests := []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{name: "not found", err: pds.ErrEvaluationNotFound, status: http.StatusNotFound, body: "evaluation_not_found"},
		{name: "concurrent modification", err: pds.ErrConcurrentModification, status: http.StatusConflict, body: "concurrent_modification"},
		{name: "missing evidence binding", err: pds.ErrEvidenceBindingMissing, status: http.StatusConflict, body: "evidence_binding_missing"},
		{name: "unknown internal failure", err: secret, status: http.StatusInternalServerError, body: "internal_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			new(Handler).writeServiceError(recorder, test.err)
			if recorder.Code != test.status {
				t.Fatalf("expected status %d, got %d", test.status, recorder.Code)
			}
			if !strings.Contains(recorder.Body.String(), test.body) {
				t.Fatalf("expected body to contain %q, got %q", test.body, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "do-not-expose") {
				t.Fatalf("internal error leaked to client: %s", recorder.Body.String())
			}
		})
	}
}

func TestEvidenceErrorMappingDoesNotExposeInternalFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	new(Handler).writeEvidenceError(recorder, errors.New("postgres host=secret.internal"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
	if recorder.Body.String() != "{\"error\":\"internal_error\"}\n" {
		t.Fatalf("unexpected public error: %s", recorder.Body.String())
	}
}

func perform(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body string,
	wantStatus int,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("%s %s: status=%d body=%s", method, path, response.Code, response.Body.String())
	}
	return response
}

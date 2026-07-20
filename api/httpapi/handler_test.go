package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cargoos/evaluation"
	"cargoos/pds"
)

func TestEvaluationDecisionTraceFlow(t *testing.T) {
	now := time.Date(2026, 7, 20, 14, 0, 0, 0, time.UTC)
	service := pds.NewService(func() time.Time {
		now = now.Add(time.Second)
		return now
	})
	handler := NewHandler(service)

	created := perform(t, handler, http.MethodPost, "/v1/evaluations",
		`{"required_rule_ids":["weight"]}`, http.StatusCreated)
	var snapshot evaluation.EvaluationSnapshot
	if err := json.Unmarshal(created.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	id := snapshot.EvaluationID.String()

	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/start", "", http.StatusOK)
	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/outcomes",
		`{"rule_id":"weight","status":"PASS"}`, http.StatusOK)
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

func TestCompletionRejectsMissingRequiredRule(t *testing.T) {
	now := time.Now().UTC()
	handler := NewHandler(pds.NewService(func() time.Time {
		now = now.Add(time.Second)
		return now
	}))
	created := perform(t, handler, http.MethodPost, "/v1/evaluations",
		`{"required_rule_ids":["weight"]}`, http.StatusCreated)
	var snapshot evaluation.EvaluationSnapshot
	_ = json.Unmarshal(created.Body.Bytes(), &snapshot)
	id := snapshot.EvaluationID.String()
	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/start", "", http.StatusOK)
	perform(t, handler, http.MethodPost, "/v1/evaluations/"+id+"/complete", "", http.StatusConflict)
}

func TestHealth(t *testing.T) {
	perform(t, NewHandler(pds.NewService(nil)), http.MethodGet, "/healthz", "", http.StatusOK)
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

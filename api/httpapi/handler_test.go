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
	tests := []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{name: "not found", err: pds.ErrEvaluationNotFound, status: http.StatusNotFound, body: "evaluation_not_found"},
		{name: "concurrent modification", err: pds.ErrConcurrentModification, status: http.StatusConflict, body: "concurrent_modification"},
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
		})
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

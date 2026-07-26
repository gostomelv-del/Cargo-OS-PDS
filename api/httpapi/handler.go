package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
	"cargoos/policy"
)

type Handler struct {
	service         *pds.Service
	evidenceService *evidence.Service
	policyResolver  pds.PolicyResolver
	ruleExecutor    RuleExecutor
	readiness       ReadinessChecker
}

const maxRequestBodyBytes int64 = 1 << 20

type RuleExecutor interface {
	Execute(context.Context, uuid.UUID) (evaluation.EvaluationSnapshot, error)
}

func NewHandler(service *pds.Service) http.Handler {
	return NewHandlerWithReadiness(service, ReadinessFunc(func(context.Context) error { return nil }))
}

type ReadinessChecker interface {
	Check(context.Context) error
}

type ReadinessFunc func(context.Context) error

func (f ReadinessFunc) Check(ctx context.Context) error {
	return f(ctx)
}

func NewHandlerWithReadiness(service *pds.Service, readiness ReadinessChecker) http.Handler {
	return NewHandlerWithEvidence(service, defaultEvidenceService(), readiness)
}

func NewHandlerWithEvidence(
	service *pds.Service,
	evidenceService *evidence.Service,
	readiness ReadinessChecker,
) http.Handler {
	return NewHandlerWithPolicyResolver(service, evidenceService, nil, readiness)
}

func NewHandlerWithPolicyResolver(
	service *pds.Service,
	evidenceService *evidence.Service,
	policyResolver pds.PolicyResolver,
	readiness ReadinessChecker,
) http.Handler {
	return NewHandlerWithRuntime(service, evidenceService, policyResolver, nil, readiness)
}

func NewHandlerWithRuntime(
	service *pds.Service,
	evidenceService *evidence.Service,
	policyResolver pds.PolicyResolver,
	ruleExecutor RuleExecutor,
	readiness ReadinessChecker,
) http.Handler {
	if readiness == nil {
		readiness = ReadinessFunc(func(context.Context) error { return nil })
	}
	if evidenceService == nil {
		evidenceService = defaultEvidenceService()
	}
	return &Handler{
		service: service, evidenceService: evidenceService,
		policyResolver: policyResolver, ruleExecutor: ruleExecutor, readiness: readiness,
	}
}

func defaultEvidenceService() *evidence.Service {
	service, err := evidence.NewService(evidence.NewMemoryRepository(), evidence.ServiceConfig{
		SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.dev",
	})
	if err != nil {
		panic(err)
	}
	return service
}

type createEvaluationRequest struct {
	SessionID string `json:"session_id"`
	PolicyID  string `json:"policy_id"`
}

type ingestEvidenceRequest struct {
	EvidenceID   string            `json:"evidence_id"`
	SessionID    string            `json:"session_id"`
	SourceID     string            `json:"source_id"`
	SourceType   string            `json:"source_type"`
	EvidenceType evidence.Type     `json:"evidence_type"`
	ObservedAt   time.Time         `json:"observed_at"`
	Payload      json.RawMessage   `json:"payload"`
	Confidence   *float64          `json:"confidence,omitempty"`
	Provenance   map[string]string `json:"provenance,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	}
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/readyz" && r.Method == http.MethodGet {
		if err := h.readiness.Check(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	}
	if r.URL.Path == "/v1/evaluations" && r.Method == http.MethodPost {
		h.createEvaluation(w, r)
		return
	}
	if r.URL.Path == "/v1/evidence" && r.Method == http.MethodPost {
		h.ingestEvidence(w, r)
		return
	}
	const evidencePrefix = "/v1/evidence/"
	if strings.HasPrefix(r.URL.Path, evidencePrefix) && r.Method == http.MethodGet {
		h.findEvidence(w, r, strings.TrimPrefix(r.URL.Path, evidencePrefix))
		return
	}
	const sessionPrefix = "/v1/sessions/"
	if strings.HasPrefix(r.URL.Path, sessionPrefix) && r.Method == http.MethodGet {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, sessionPrefix), "/")
		if len(parts) == 2 && parts[1] == "evidence" {
			h.listSessionEvidence(w, r, parts[0])
			return
		}
	}
	const prefix = "/v1/evaluations/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	id, err := uuid.Parse(parts[0])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_evaluation_id")
		return
	}
	switch {
	case parts[1] == "start" && r.Method == http.MethodPost:
		snapshot, serviceErr := h.service.Start(r.Context(), id)
		h.writeServiceResult(w, snapshot, serviceErr)
	case parts[1] == "execute-rules" && r.Method == http.MethodPost:
		h.executeRules(w, r, id)
	case parts[1] == "complete" && r.Method == http.MethodPost:
		trace, serviceErr := h.service.Complete(r.Context(), id)
		h.writeServiceResult(w, trace, serviceErr)
	case parts[1] == "decision-trace" && r.Method == http.MethodGet:
		trace, serviceErr := h.service.Trace(r.Context(), id)
		h.writeServiceResult(w, trace, serviceErr)
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
}

func (h *Handler) executeRules(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var request struct{}
	if err := decodeOptionalJSON(r, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if h.ruleExecutor == nil {
		writeError(w, http.StatusServiceUnavailable, "rule_executor_unavailable")
		return
	}
	snapshot, err := h.ruleExecutor.Execute(r.Context(), id)
	h.writeServiceResult(w, snapshot, err)
}

func (h *Handler) ingestEvidence(w http.ResponseWriter, r *http.Request) {
	var request ingestEvidenceRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	sessionID, err := uuid.Parse(request.SessionID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_session_id")
		return
	}
	var evidenceID uuid.UUID
	if request.EvidenceID != "" {
		evidenceID, err = uuid.Parse(request.EvidenceID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_evidence_id")
			return
		}
	}
	snapshot, err := h.evidenceService.Ingest(r.Context(), evidence.Input{
		EvidenceID: evidenceID, SessionID: sessionID, SourceID: request.SourceID,
		SourceType: request.SourceType, EvidenceType: request.EvidenceType,
		ObservedAt: request.ObservedAt, Payload: request.Payload,
		Confidence: request.Confidence, Provenance: request.Provenance,
		AcquisitionMethod: "HTTP",
	})
	if err != nil {
		h.writeEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, snapshot)
}

func (h *Handler) findEvidence(w http.ResponseWriter, r *http.Request, value string) {
	if value == "" || strings.Contains(value, "/") {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	id, err := uuid.Parse(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_evidence_id")
		return
	}
	snapshot, err := h.evidenceService.Find(r.Context(), id)
	if err != nil {
		h.writeEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) listSessionEvidence(w http.ResponseWriter, r *http.Request, value string) {
	id, err := uuid.Parse(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_session_id")
		return
	}
	snapshots, err := h.evidenceService.ListBySession(r.Context(), id)
	if err != nil {
		h.writeEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshots)
}

func (h *Handler) writeEvidenceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, evidence.ErrNotFound):
		writeError(w, http.StatusNotFound, "evidence_not_found")
	case errors.Is(err, evidence.ErrConflict):
		writeError(w, http.StatusConflict, "evidence_conflict")
	case isEvidenceInputError(err):
		writeError(w, http.StatusBadRequest, "invalid_evidence")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

func isEvidenceInputError(err error) bool {
	return errors.Is(err, evidence.ErrSessionIDRequired) ||
		errors.Is(err, evidence.ErrSourceIDRequired) ||
		errors.Is(err, evidence.ErrSourceTypeRequired) ||
		errors.Is(err, evidence.ErrInvalidEvidenceType) ||
		errors.Is(err, evidence.ErrObservedAtRequired) ||
		errors.Is(err, evidence.ErrInvalidTimestampOrder) ||
		errors.Is(err, evidence.ErrInvalidPayload) ||
		errors.Is(err, evidence.ErrInvalidConfidence)
}

func (h *Handler) createEvaluation(w http.ResponseWriter, r *http.Request) {
	var request createEvaluationRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	sessionID := uuid.New()
	if request.SessionID != "" {
		parsed, err := uuid.Parse(request.SessionID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_session_id")
			return
		}
		sessionID = parsed
	}
	snapshot, err := h.service.CreateForPolicy(r.Context(), sessionID, request.PolicyID, h.policyResolver)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, snapshot)
}

func (h *Handler) writeServiceResult(w http.ResponseWriter, value any, err error) {
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pds.ErrEvaluationNotFound):
		writeError(w, http.StatusNotFound, "evaluation_not_found")
	case errors.Is(err, pds.ErrConcurrentModification):
		writeError(w, http.StatusConflict, "concurrent_modification")
	case errors.Is(err, pds.ErrPolicyResolverRequired):
		writeError(w, http.StatusServiceUnavailable, "policy_resolver_unavailable")
	case errors.Is(err, policy.ErrPolicyNotFound):
		writeError(w, http.StatusNotFound, "active_policy_not_found")
	case errors.Is(err, evaluation.ErrRequiredRulesIncomplete):
		writeError(w, http.StatusConflict, "required_rules_incomplete")
	case errors.Is(err, evaluation.ErrInvalidStateTransition):
		writeError(w, http.StatusConflict, "invalid_state_transition")
	case errors.Is(err, evaluation.ErrRuleOutcomeConflict):
		writeError(w, http.StatusConflict, "rule_outcome_conflict")
	case errors.Is(err, pds.ErrEvidenceBindingMissing):
		writeError(w, http.StatusConflict, "evidence_binding_missing")
	case errors.Is(err, pds.ErrPolicyBindingMissing):
		writeError(w, http.StatusConflict, "policy_binding_missing")
	case errors.Is(err, pds.ErrEvidenceNotQualified):
		writeError(w, http.StatusConflict, "evidence_not_qualified")
	case errors.Is(err, pds.ErrPartialRuleOutcomes):
		writeError(w, http.StatusConflict, "partial_rule_outcomes")
	case errors.Is(err, pds.ErrRuleOperatorMissing):
		writeError(w, http.StatusUnprocessableEntity, "policy_rule_unavailable")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireJSONEnd(decoder)
}

func decodeOptionalJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(target)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return requireJSONEnd(decoder)
}

func requireJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("httpapi: request body must contain one JSON value")
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request_body_too_large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_json")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSONStatus(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	writeJSONStatus(w, status, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

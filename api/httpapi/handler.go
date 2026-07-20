package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/pds"
)

type Handler struct {
	service *pds.Service
}

func NewHandler(service *pds.Service) http.Handler {
	return &Handler{service: service}
}

type createEvaluationRequest struct {
	SessionID       string   `json:"session_id"`
	RequiredRuleIDs []string `json:"required_rule_ids"`
}

type recordOutcomeRequest struct {
	RuleID      string   `json:"rule_id"`
	Status      string   `json:"status"`
	ReasonCodes []string `json:"reason_codes"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/v1/evaluations" && r.Method == http.MethodPost {
		h.createEvaluation(w, r)
		return
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
	case parts[1] == "outcomes" && r.Method == http.MethodPost:
		h.recordOutcome(w, r, id)
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

func (h *Handler) createEvaluation(w http.ResponseWriter, r *http.Request) {
	var request createEvaluationRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
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
	snapshot, err := h.service.Create(r.Context(), sessionID, request.RequiredRuleIDs)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, snapshot)
}

func (h *Handler) recordOutcome(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var request recordOutcomeRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	reasons := make([]evaluation.ReasonCode, 0, len(request.ReasonCodes))
	for _, value := range request.ReasonCodes {
		reason, err := evaluation.NewReasonCode(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_reason_code")
			return
		}
		reasons = append(reasons, reason)
	}
	snapshot, err := h.service.RecordOutcome(r.Context(), id, evaluation.RuleOutcome{
		RuleID: request.RuleID, Status: evaluation.RuleOutcomeStatus(request.Status), ReasonCodes: reasons,
	})
	h.writeServiceResult(w, snapshot, err)
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
	case errors.Is(err, evaluation.ErrRequiredRulesIncomplete),
		errors.Is(err, evaluation.ErrInvalidStateTransition),
		errors.Is(err, evaluation.ErrRuleOutcomeConflict):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
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

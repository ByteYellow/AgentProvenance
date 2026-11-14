package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/byteyellow/agentprovenance/internal/handoff"
)

type ExecutionAdmission struct {
	SchemaVersion string          `json:"schema_version"`
	Attempt       handoff.Attempt `json:"attempt"`
	Reused        bool            `json:"reused"`
}

func executionError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"schema_version": handoff.SchemaVersion, "error": code})
}

func executionFailure(w http.ResponseWriter, err error) {
	for _, known := range []struct {
		err    error
		status int
	}{
		{handoff.ErrInvalid, http.StatusBadRequest}, {handoff.ErrForbidden, http.StatusForbidden},
		{handoff.ErrNotFound, http.StatusNotFound}, {handoff.ErrConflict, http.StatusConflict},
		{handoff.ErrStale, http.StatusConflict}, {handoff.ErrExpired, http.StatusGone},
		{handoff.ErrDeliveryRetired, http.StatusGone},
	} {
		if errors.Is(err, known.err) {
			executionError(w, known.status, known.err.Error())
			return
		}
	}
	executionError(w, http.StatusInternalServerError, "execution_storage_failed")
}

func (s Server) executionEnabled(w http.ResponseWriter) bool {
	if s.Execution == nil {
		executionError(w, http.StatusNotFound, "execution_not_enabled")
		return false
	}
	if s.AuthToken == "" {
		executionError(w, http.StatusForbidden, "execution_authentication_required")
		return false
	}
	return true
}

func decodeExecution(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	err := d.Decode(target)
	if err == nil {
		if extra := d.Decode(new(any)); extra != io.EOF {
			err = handoff.ErrInvalid
			if extra != nil {
				err = extra
			}
		}
	}
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			executionError(w, http.StatusRequestEntityTooLarge, "execution_request_too_large")
		} else {
			executionError(w, http.StatusBadRequest, handoff.ErrInvalid.Error())
		}
		return false
	}
	return true
}

func (s Server) submitExecution(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled(w) {
		return
	}
	if !s.Execution.Running() {
		executionError(w, http.StatusServiceUnavailable, "execution_worker_unavailable")
		return
	}
	var request handoff.Request
	if !decodeExecution(w, r, &request) {
		return
	}
	a, reused, err := s.Execution.Ledger.Admit(r.Context(), s.ExecutionCaller, request)
	if err != nil {
		executionFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/v1/executions/"+a.ID)
	if !reused {
		w.WriteHeader(http.StatusAccepted)
	}
	writeJSON(w, ExecutionAdmission{SchemaVersion: handoff.SchemaVersion, Attempt: a, Reused: reused})
}

func (s Server) getExecution(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled(w) {
		return
	}
	report, err := s.Execution.Ledger.Report(r.Context(), s.ExecutionCaller, r.PathValue("id"))
	if err != nil {
		executionFailure(w, err)
		return
	}
	writeJSON(w, report)
}

func (s Server) listExecutions(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled(w) {
		return
	}
	q := r.URL.Query()
	after, limit := int64(0), 50
	var err error
	if q.Get("after") != "" {
		after, err = strconv.ParseInt(q.Get("after"), 10, 64)
	}
	if err == nil && q.Get("limit") != "" {
		limit, err = strconv.Atoi(q.Get("limit"))
	}
	if err != nil {
		executionFailure(w, handoff.ErrInvalid)
		return
	}
	source := handoff.Source{ProducerID: s.ExecutionCaller.ProducerID, Namespace: s.ExecutionCaller.Namespace,
		RunID: q.Get("run"), Harness: q.Get("harness"), SessionID: q.Get("session"), ToolCallID: q.Get("tool_call")}
	page, err := s.Execution.Ledger.List(r.Context(), s.ExecutionCaller, source, after, limit)
	if err != nil {
		executionFailure(w, err)
		return
	}
	writeJSON(w, page)
}

func (s Server) stopExecution(w http.ResponseWriter, r *http.Request) {
	if !s.executionEnabled(w) {
		return
	}
	var request struct {
		OperationID string `json:"operation_id"`
	}
	if !decodeExecution(w, r, &request) {
		return
	}
	receipt, err := s.Execution.Ledger.RequestStop(r.Context(), s.ExecutionCaller, r.PathValue("id"), request.OperationID)
	if err != nil {
		executionFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, receipt)
}

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/byteyellow/agentprovenance/internal/handoff"
)

const executionTransferTimeout = 2 * time.Minute

func (s Server) reconcileExecutionPublications(ctx context.Context, limit int) {
	ctx, cancel := context.WithTimeout(ctx, executionTransferTimeout)
	defer cancel()
	result, cleanupErr := s.ExecutionDelivery.ReconcilePublications(ctx, limit)
	if result.Removed == 0 && cleanupErr == nil {
		return
	}
	record := struct {
		handoff.PublicationCleanup
		Error string `json:"error,omitempty"`
	}{PublicationCleanup: result}
	if cleanupErr != nil {
		record.Error = cleanupErr.Error()
		log.Printf("execution publication cleanup: %v", cleanupErr)
	}
	raw, err := json.Marshal(record)
	if err == nil {
		_, err = s.DB.ExecContext(ctx, `INSERT INTO events(id,source,event_type,payload,created_at)
			VALUES ('evt-' || lower(hex(randomblob(6))), 'daemon_gc', 'execution_publication_cleanup', ?, ?)`, string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	}
	if err != nil {
		log.Printf("persist execution publication cleanup result: %v", err)
	}
}

type ExecutionDeliveryResponse struct {
	SchemaVersion string           `json:"schema_version"`
	Delivery      handoff.Delivery `json:"delivery"`
	Reused        bool             `json:"reused"`
}

func (s Server) deliveryEnabled(w http.ResponseWriter) bool {
	if !s.executionEnabled(w) {
		return false
	}
	if s.ExecutionDelivery == nil {
		executionError(w, http.StatusNotFound, "execution_delivery_not_enabled")
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	return true
}

func (s Server) prepareExecutionDelivery(w http.ResponseWriter, r *http.Request) {
	if !s.deliveryEnabled(w) {
		return
	}
	var request struct {
		OperationID string `json:"operation_id"`
	}
	if !decodeExecution(w, r, &request) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), executionTransferTimeout)
	defer cancel()
	d, reused, err := s.ExecutionDelivery.Prepare(ctx, s.ExecutionCaller, r.PathValue("id"), request.OperationID)
	if err != nil {
		executionFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/v1/execution-deliveries/"+d.Manifest.ID)
	if !reused {
		w.WriteHeader(http.StatusCreated)
	}
	writeJSON(w, ExecutionDeliveryResponse{handoff.DeliverySchema, d, reused})
}

func (s Server) getExecutionDelivery(w http.ResponseWriter, r *http.Request) {
	if !s.deliveryEnabled(w) {
		return
	}
	d, err := s.ExecutionDelivery.Get(r.Context(), s.ExecutionCaller, r.PathValue("id"))
	if err != nil {
		executionFailure(w, err)
		return
	}
	writeJSON(w, ExecutionDeliveryResponse{handoff.DeliverySchema, d, true})
}

func (s Server) downloadExecutionDelivery(w http.ResponseWriter, r *http.Request) {
	if !s.deliveryEnabled(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), executionTransferTimeout)
	defer cancel()
	d, f, err := s.ExecutionDelivery.OpenBundle(ctx, s.ExecutionCaller, r.PathValue("id"))
	if err != nil {
		executionFailure(w, err)
		return
	}
	defer f.Close()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(executionTransferTimeout))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="execution-bundle.json"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.FormatInt(d.Manifest.BundleBytes, 10))
	w.Header().Set("ETag", `"sha256:`+d.Manifest.BundleSHA256+`"`)
	// A broken connection leaves the immutable package pending for a full retry.
	_, _ = io.CopyN(w, f, d.Manifest.BundleBytes)
}

func (s Server) acknowledgeExecutionDelivery(w http.ResponseWriter, r *http.Request) {
	if !s.deliveryEnabled(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, handoff.MaxEnvelopeBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			executionError(w, http.StatusRequestEntityTooLarge, "execution_receipt_too_large")
		} else {
			executionFailure(w, handoff.ErrInvalid)
		}
		return
	}
	d, err := s.ExecutionDelivery.Acknowledge(r.Context(), s.ExecutionCaller, r.PathValue("id"), raw)
	if err != nil {
		executionFailure(w, err)
		return
	}
	writeJSON(w, ExecutionDeliveryResponse{handoff.DeliverySchema, d, true})
}

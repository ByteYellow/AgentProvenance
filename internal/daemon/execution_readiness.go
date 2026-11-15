package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/handoff"
)

// ExecutionReadiness is an authenticated, read-only configuration view. Key
// fingerprints are derived from public keys; credentials and paths stay local.
type ExecutionReadiness struct {
	SchemaVersion     string         `json:"schema_version"`
	Target            handoff.Target `json:"target"`
	PrincipalID       string         `json:"principal_id"`
	SourceProducerID  string         `json:"source_producer_id"`
	SourceNamespace   string         `json:"source_namespace"`
	WorkerRunning     bool           `json:"worker_running"`
	NativeCapture     bool           `json:"native_capture"`
	CaptureReady      bool           `json:"capture_ready"`
	ReceiverID        string         `json:"receiver_id"`
	TargetKeySHA256   string         `json:"target_key_sha256"`
	ReceiverKeySHA256 string         `json:"receiver_key_sha256"`
}

func (s Server) executionReadiness(w http.ResponseWriter, _ *http.Request) {
	if !s.executionEnabled(w) {
		return
	}
	r := ExecutionReadiness{SchemaVersion: handoff.SchemaVersion, Target: s.Execution.Ledger.Target,
		PrincipalID: s.ExecutionCaller.ID, SourceProducerID: s.ExecutionCaller.ProducerID,
		SourceNamespace: s.ExecutionCaller.Namespace, WorkerRunning: s.Execution.Running(), NativeCapture: s.Execution.Capture != nil}
	if c := s.Execution.Capture; c != nil && c.Capabilities != nil {
		r.CaptureReady = c.Capabilities().Ready
	}
	if d := s.ExecutionDelivery; d != nil && len(d.SignKey) == ed25519.PrivateKeySize && len(d.ReceiverKey) == ed25519.PublicKeySize {
		r.ReceiverID = d.ReceiverID
		r.TargetKeySHA256 = attest.DigestSHA256(d.SignKey.Public().(ed25519.PublicKey))
		r.ReceiverKeySHA256 = attest.DigestSHA256(d.ReceiverKey)
	}
	writeJSON(w, r)
}

func (c Client) ExecutionReadiness(ctx context.Context) (ExecutionReadiness, error) {
	var out ExecutionReadiness
	r, err := c.deliveryHTTP(ctx, http.MethodGet, "/v1/execution-readiness", nil)
	if err != nil {
		return out, err
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxDeliveryResponseBytes+1))
	if err != nil {
		return out, err
	}
	if len(raw) > maxDeliveryResponseBytes {
		return out, fmt.Errorf("execution readiness response exceeds limit")
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	if out.SchemaVersion != handoff.SchemaVersion || out.Target.Validate() != nil {
		return out, fmt.Errorf("invalid execution readiness response")
	}
	return out, nil
}

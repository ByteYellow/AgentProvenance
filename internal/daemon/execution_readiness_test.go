package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func TestExecutionReadinessRequiresAuthenticationAndDoesNotDispatch(t *testing.T) {
	s, _, receiver := deliveryServer(t)
	handler := s.Handler()
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/v1/execution-readiness", nil))
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("unprotected readiness: %d", denied.Code)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := Client{BaseURL: server.URL, Token: s.AuthToken, HTTP: server.Client()}
	r, err := client.ExecutionReadiness(context.Background())
	if err != nil || !r.WorkerRunning || r.Target != s.Execution.Ledger.Target || r.ReceiverID != receiver.ID || r.NativeCapture || r.CaptureReady {
		t.Fatalf("readiness: %+v %v", r, err)
	}
	if r.TargetKeySHA256 != attest.DigestSHA256(receiver.TargetKey) || r.ReceiverKeySHA256 != attest.DigestSHA256(receiver.SignKey.Public().(ed25519.PublicKey)) {
		t.Fatal("public key fingerprints differ")
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), s.AuthToken) || strings.Contains(string(raw), hex.EncodeToString(s.ExecutionDelivery.SignKey)) {
		t.Fatal("readiness exposed private credentials")
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM execution_attempts").Scan(&count); err != nil || count != 0 {
		t.Fatalf("readiness created execution: %d %v", count, err)
	}
	for _, ready := range []bool{false, true} {
		// Call the handler directly after configuring a collector; no execution
		// is submitted and no running worker reads its capture field.
		s.Execution = &handoff.Executor{Ledger: s.Execution.Ledger,
			Capture: &handoff.NativeCapture{Capabilities: func() sensor.CapabilityReport { return sensor.CapabilityReport{Ready: ready} }}}
		out := httptest.NewRecorder()
		s.executionReadiness(out, httptest.NewRequest(http.MethodGet, "/v1/execution-readiness", nil))
		if err := json.Unmarshal(out.Body.Bytes(), &r); err != nil || !r.NativeCapture || r.CaptureReady != ready {
			t.Fatalf("capture readiness: %+v %v", r, err)
		}
	}
}

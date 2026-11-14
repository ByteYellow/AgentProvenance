package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func deliveryServer(t *testing.T) (Server, handoff.Request, *handoff.DeliveryReceiver) {
	t.Helper()
	s, request := executionServer(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recvPub, recvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s.ExecutionDelivery = &handoff.DeliveryService{Ledger: s.Execution.Ledger, Paths: s.Paths, SignKey: key, ReceiverID: "receiver", ReceiverKey: recvPub}
	receiver := &handoff.DeliveryReceiver{DB: db, Paths: paths, ID: "receiver", SignKey: recvKey, Target: request.Target, TargetKey: pub, Caller: s.ExecutionCaller}
	return s, request, receiver
}

func TestExecutionDeliveryAPILostAcknowledgment(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		t.Run(map[bool]string{false: "request_lost", true: "response_lost"}[persisted], func(t *testing.T) {
			s, request, receiver := deliveryServer(t)
			handler := s.Handler()
			var acknowledgments atomic.Int32
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/receipt") && acknowledgments.Add(1) == 1 {
					if persisted {
						saved := httptest.NewRecorder()
						handler.ServeHTTP(saved, r)
						if saved.Code != 200 {
							t.Errorf("failed to persist ACK: %s", saved.Body.String())
						}
					}
					http.Error(w, "connection unavailable", 503)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer httpServer.Close()
			client := Client{BaseURL: httpServer.URL, HTTP: httpServer.Client(), Token: s.AuthToken}
			admission, err := client.SubmitExecution(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			waitAPIExecution(t, client, admission.Attempt.ID, handoff.Succeeded)
			expected := handoff.IdentityOf(admission.Attempt)
			partial, err := client.CollectExecution(context.Background(), expected, "collect-1", receiver)
			if err == nil || partial.Status != "receipt_persisted" || len(partial.Receipt) == 0 {
				t.Fatalf("lost ACK: %+v %v", partial, err)
			}
			result, err := client.CollectExecution(context.Background(), expected, "collect-1", receiver)
			if err != nil || result.Status != "acknowledged" || !bytes.Equal(result.Receipt, partial.Receipt) {
				t.Fatalf("recovery: %+v %v", result, err)
			}
			report, err := client.Execution(context.Background(), admission.Attempt.ID)
			if err != nil || report.Attempt.State.Delivery != handoff.Acknowledged || report.Attempt.State.Capture != handoff.Draining {
				t.Fatalf("state dimensions changed: %+v %v", report, err)
			}
			for _, table := range []string{"execution_deliveries", "tool_calls"} {
				var count int
				if err := s.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
					t.Fatalf("repeated side effect %s: %d %v", table, count, err)
				}
			}
			var count int
			if err := receiver.DB.QueryRow("SELECT COUNT(*) FROM execution_delivery_receipts").Scan(&count); err != nil || count != 1 {
				t.Fatalf("duplicate receipt: %d %v", count, err)
			}
			if err := receiver.DB.QueryRow("SELECT COUNT(*) FROM events WHERE run_id=?", expected.LocalRunID).Scan(&count); err != nil || count == 0 {
				t.Fatalf("no received evidence: %d %v", count, err)
			}
			got, err := client.ExecutionDelivery(context.Background(), result.DeliveryID)
			if err != nil || got.Delivery.Manifest.Identity != expected || got.Delivery.BundlePath != "" {
				t.Fatalf("metadata: %+v %v", got, err)
			}
		})
	}
}

func TestExecutionDeliveryAPIRetiredPackageAndGC(t *testing.T) {
	s, request, receiver := deliveryServer(t)
	s.ExecutionDelivery.Retention = time.Hour
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	client := Client{BaseURL: server.URL, HTTP: server.Client(), Token: s.AuthToken}
	ctx := context.Background()
	a, err := client.SubmitExecution(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	waitAPIExecution(t, client, a.Attempt.ID, handoff.Succeeded)
	result, err := client.CollectExecution(ctx, handoff.IdentityOf(a.Attempt), "retention", receiver)
	if err != nil {
		t.Fatal(err)
	}
	s.ExecutionDelivery.Ledger.Now = func() time.Time { return request.ValidUntil.Add(2 * time.Hour) }
	s.gcOnce(ctx)
	got, err := client.ExecutionDelivery(ctx, result.DeliveryID)
	if err != nil || got.Delivery.Storage == nil || got.Delivery.Storage.PurgedAt == nil || !bytes.Equal(got.Delivery.Receipt, result.Receipt) {
		t.Fatalf("retained metadata: %+v %v", got.Delivery.Storage, err)
	}
	for _, route := range []struct{ method, path, body string }{
		{"GET", "/v1/execution-deliveries/" + result.DeliveryID + "/bundle", ""},
		{"POST", "/v1/executions/" + a.Attempt.ID + "/deliveries", `{"operation_id":"retention"}`},
	} {
		r := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
		r.Header.Set("Authorization", "Bearer "+s.AuthToken)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), `"error":"execution_delivery_retired"`) {
			t.Fatalf("retired %s: %d %s", route.path, w.Code, w.Body.String())
		}
	}
	var payload string
	if err := s.DB.QueryRow(`SELECT payload FROM events WHERE event_type='execution_delivery_cleanup'`).Scan(&payload); err != nil || !strings.Contains(payload, `"purged":1`) {
		t.Fatalf("cleanup result unavailable: %q %v", payload, err)
	}
}

func TestExecutionDeliveryGCReconcilesFailedPublication(t *testing.T) {
	s, request, _ := deliveryServer(t)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	client := Client{BaseURL: server.URL, HTTP: server.Client(), Token: s.AuthToken}
	ctx := context.Background()
	a, err := client.SubmitExecution(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	waitAPIExecution(t, client, a.Attempt.ID, handoff.Succeeded)
	kept, err := client.PrepareExecutionDelivery(ctx, a.Attempt.ID, "kept")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER reject_delivery BEFORE INSERT ON execution_deliveries
		BEGIN SELECT RAISE(ABORT,'injected publication failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PrepareExecutionDelivery(ctx, a.Attempt.ID, "failed"); err == nil {
		t.Fatal("database publication failure was hidden")
	}
	root := filepath.Join(s.Paths.Artifacts, "execution-deliveries")
	packages, err := filepath.Glob(filepath.Join(root, "package-*"))
	if err != nil || len(packages) != 2 {
		t.Fatalf("failure did not reach publication: %v %v", packages, err)
	}
	s.gcOnce(ctx)
	packages, err = filepath.Glob(filepath.Join(root, "package-*"))
	if err != nil || len(packages) != 1 {
		t.Fatalf("GC retained an unreferenced publication: %v %v", packages, err)
	}
	d, reader, err := s.ExecutionDelivery.OpenBundle(ctx, s.ExecutionCaller, kept.Delivery.Manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if n, err := io.Copy(io.Discard, reader); err != nil || n != d.Manifest.BundleBytes {
		t.Fatalf("GC damaged pending delivery: %d %v", n, err)
	}
}

func TestExecutionDeliveryAPIRejectsUnauthorizedAndCorrupt(t *testing.T) {
	s, request, receiver := deliveryServer(t)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	client := Client{BaseURL: server.URL, HTTP: server.Client(), Token: s.AuthToken}
	a, err := client.SubmitExecution(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	waitAPIExecution(t, client, a.Attempt.ID, handoff.Succeeded)
	d, err := client.PrepareExecutionDelivery(context.Background(), a.Attempt.ID, "collect")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, body, token, origin, contentType string
		code                                           int
	}{
		{"POST", "/v1/executions/" + a.Attempt.ID + "/deliveries", `{"operation_id":"other"}`, "", "", "application/json", 401},
		{"GET", "/v1/execution-deliveries/" + d.Delivery.Manifest.ID + "/bundle", "", "", "", "", 401},
		{"POST", "/v1/execution-deliveries/" + d.Delivery.Manifest.ID + "/receipt", `{}`, s.AuthToken, "https://evil.example", "application/json", 403},
		{"POST", "/v1/execution-deliveries/" + d.Delivery.Manifest.ID + "/receipt", `{}`, s.AuthToken, "", "text/plain", 403},
		{"POST", "/v1/execution-deliveries/" + d.Delivery.Manifest.ID + "/receipt", `{}`, s.AuthToken, "", "application/json", 400},
		{"POST", "/v1/execution-deliveries/" + d.Delivery.Manifest.ID + "/receipt", strings.Repeat(" ", handoff.MaxEnvelopeBytes+1), s.AuthToken, "", "application/json", 413},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.contentType)
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Errorf("%s: %d want %d %s", tc.path, w.Code, tc.code, w.Body.String())
		}
	}
	// A modified trusted key must be rejected before requesting any body bytes.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	receiver.TargetKey = other
	if _, err := client.CollectExecution(context.Background(), handoff.IdentityOf(a.Attempt), "collect", receiver); err == nil {
		t.Fatal("untrusted signing key accepted")
	}
	var count int
	if err := receiver.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 0 {
		t.Fatalf("bad signature imported: %d %v", count, err)
	}
	saved, err := s.ExecutionDelivery.Get(context.Background(), s.ExecutionCaller, d.Delivery.Manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saved.BundlePath, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if response, err := client.deliveryHTTP(context.Background(), "GET", "/v1/execution-deliveries/"+saved.Manifest.ID+"/bundle", nil); err == nil {
		response.Body.Close()
		t.Fatal("damaged archive downloaded as success")
	}
}

func TestExecutionDeliveryClientLimitsRedirectsAndCancellation(t *testing.T) {
	var forwarded atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
	defer destination.Close()
	for _, mode := range []string{"redirect", "oversized", "invalid_schema"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
				case "oversized":
					io.WriteString(w, strings.Repeat(" ", maxDeliveryResponseBytes+1))
				default:
					json.NewEncoder(w).Encode(map[string]string{"schema_version": "other"})
				}
			}))
			defer server.Close()
			client := Client{BaseURL: server.URL, Token: "secret", HTTP: server.Client()}
			if _, err := client.PrepareExecutionDelivery(context.Background(), "attempt", "operation"); err == nil {
				t.Fatal("accepted invalid transport response")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := client.PrepareExecutionDelivery(ctx, "attempt", "operation"); err == nil {
				t.Fatal("ignored cancellation")
			}
		})
	}
	if forwarded.Load() != 0 {
		t.Fatal("followed credential-bearing redirect")
	}
}

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/handoff"
)

func executionServer(t *testing.T) (Server, handoff.Request) {
	t.Helper()
	s := testServer(t)
	s.AuthToken = "test-execution-token"
	target := handoff.Target{ProducerID: "vm-producer", InstanceID: "vm-one", Generation: "boot-one"}
	s.ExecutionCaller = handoff.Principal{ID: "trusted-router", ProducerID: "mac", Namespace: "local-user", AllowedTargets: []handoff.Target{target}}
	s.Execution = &handoff.Executor{Ledger: handoff.Ledger{DB: s.DB, Target: target}, Paths: s.Paths, PollInterval: 5 * time.Millisecond}
	stop, err := s.Execution.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	return s, handoff.Request{SchemaVersion: handoff.SchemaVersion, Source: handoff.Source{ProducerID: "mac", Namespace: "local-user",
		RunID: "upstream-run", Harness: "fixture", SessionID: "native-session", ToolCallID: "call-1"}, Target: target,
		DispatchID: "dispatch-1", OperationID: "operation-1", ValidUntil: time.Now().Add(time.Hour).UTC(),
		Command: handoff.Command{Argv: []string{"sleep", "0.1"}, DisableSnapshot: true, PostRootGraceMS: 1}}
}

func waitAPIExecution(t *testing.T, client Client, id string, wanted handoff.ExecutionState) handoff.Report {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var report handoff.Report
	for time.Now().Before(deadline) {
		var err error
		report, err = client.Execution(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if report.Attempt.State.Execution == wanted {
			return report
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("API execution did not reach %s: %+v", wanted, report)
	return report
}

func TestExecutionLinksAPIKeepsDaemonAuthentication(t *testing.T) {
	s := testServer(t)
	s.AuthToken = "read-fixture-token"
	h := httptest.NewServer(s.Handler())
	defer h.Close()
	c := Client{BaseURL: h.URL, HTTP: h.Client()}
	opts := handoff.ExecutionLinksOptions{RunID: "saved-run", Direction: "incoming"}
	if _, err := c.ExecutionLinks(context.Background(), opts); err == nil {
		t.Fatal("unauthenticated execution links exposed")
	}
	c.Token = s.AuthToken
	page, err := c.ExecutionLinks(context.Background(), opts)
	if err != nil || page.SchemaVersion != handoff.ExecutionLinksSchema || page.Direction != "incoming" || len(page.Links) != 0 {
		t.Fatalf("execution read route: %+v %v", page, err)
	}
	opts.Direction = "invalid"
	if _, err := c.ExecutionLinks(context.Background(), opts); err == nil {
		t.Fatal("invalid query accepted")
	}
}

func TestExecutionAPIRequestLifetimeRetryAndStop(t *testing.T) {
	s, request := executionServer(t)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	client := Client{BaseURL: server.URL, HTTP: server.Client(), Token: s.AuthToken}
	ctx, cancel := context.WithCancel(context.Background())
	admission, err := client.SubmitExecution(ctx, request)
	cancel()
	if err != nil || admission.Reused || admission.Attempt.ID == "" {
		t.Fatalf("submit: %+v %v", admission, err)
	}
	report := waitAPIExecution(t, client, admission.Attempt.ID, handoff.Succeeded)
	if report.Checkpoint.Result.EndEventID == "" || report.Checkpoint.Source != request.Source {
		t.Fatalf("missing endpoint/source evidence: %+v", report)
	}
	again, err := client.SubmitExecution(context.Background(), request)
	if err != nil || !again.Reused || again.Attempt.ID != admission.Attempt.ID {
		t.Fatalf("network retry: %+v %v", again, err)
	}
	page, err := client.Executions(context.Background(), request.Source, 0, 1)
	if err != nil || len(page.Attempts) != 1 || page.Attempts[0].ID != admission.Attempt.ID {
		t.Fatalf("source query: %+v %v", page, err)
	}
	request.OperationID, request.PreviousAttemptID, request.Command.Argv = "explicit-retry", admission.Attempt.ID, []string{"sleep", "60"}
	retry, err := client.SubmitExecution(context.Background(), request)
	if err != nil || retry.Attempt.Number != 2 {
		t.Fatalf("explicit reexecution: %+v %v", retry, err)
	}
	waitAPIExecution(t, client, retry.Attempt.ID, handoff.Running)
	stop, err := client.StopExecution(context.Background(), retry.Attempt.ID, "stop-request")
	if err != nil || stop.State != "requested" {
		t.Fatalf("stop: %+v %v", stop, err)
	}
	waitAPIExecution(t, client, retry.Attempt.ID, handoff.Cancelled)
	var executions int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM tool_calls`).Scan(&executions); err != nil || executions != 2 {
		t.Fatalf("executed %d commands: %v", executions, err)
	}
}

func TestExecutionAPIRejectsUntrustedAndMalformedRequests(t *testing.T) {
	s, request := executionServer(t)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, token, body, origin, contentType string
		want                                   int
	}{
		{"unauthenticated", "", string(raw), "", "application/json", 401},
		{"cross_origin", s.AuthToken, string(raw), "https://evil.example", "application/json", 403},
		{"simple_post", s.AuthToken, string(raw), "", "text/plain", 403},
		{"unknown_field", s.AuthToken, strings.TrimSuffix(string(raw), "}") + `,"principal_id":"other"}`, "", "application/json", 400},
		{"trailing_json", s.AuthToken, string(raw) + `{}`, "", "application/json", 400},
		{"oversized", s.AuthToken, `{"padding":"` + strings.Repeat("x", 1<<20) + `"}`, "", "application/json", 413},
		{"foreign_source", s.AuthToken, strings.Replace(string(raw), `"producer_id":"mac"`, `"producer_id":"other"`, 1), "", "application/json", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/executions", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM execution_attempts`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected request admitted: %d %v", count, err)
	}
}

func TestExecutionAPIRequiresOptInAndAuthentication(t *testing.T) {
	s := testServer(t)
	s.AuthToken = "token"
	r := httptest.NewRequest(http.MethodGet, "/v1/executions/any", nil)
	r.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("handoff enabled by default: %d", w.Code)
	}
	s.Execution = &handoff.Executor{}
	s.AuthToken = ""
	r = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/v1/executions/any", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("handoff allowed without auth: %d", w.Code)
	}
}

package dashboard

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestRedactSecretsMasksSecretShapes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		leak    string // substring that must NOT survive
		wantRed bool
	}{
		{
			name:    "private key block",
			in:      "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
			leak:    "b3BlbnNzaC1rZXktdjEAAAAA",
			wantRed: true,
		},
		{name: "aws access key", in: "id = AKIAIOSFODNN7EXAMPLE", leak: "AKIAIOSFODNN7EXAMPLE", wantRed: true},
		{name: "password assignment", in: `{"password":"hunter2supersecret"}`, leak: "hunter2supersecret", wantRed: true},
		{name: "token assignment", in: "ANTHROPIC_AUTH_TOKEN=sk-abc123def456", leak: "sk-abc123def456", wantRed: true},
		{name: "benign code", in: "def move(snake):\n    return snake.head + 1\n", leak: "", wantRed: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, red := redactSecrets(c.in)
			if red != c.wantRed {
				t.Fatalf("redacted=%v want %v (out=%q)", red, c.wantRed, out)
			}
			if c.leak != "" && contains(out, c.leak) {
				t.Fatalf("secret %q survived redaction: %q", c.leak, out)
			}
		})
	}
}

func TestIsBinaryContent(t *testing.T) {
	if !isBinaryContent([]byte{0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01}) {
		t.Fatal("NUL-containing bytes should be binary")
	}
	if isBinaryContent([]byte("print('snake')\n")) {
		t.Fatal("utf-8 text should not be binary")
	}
}

func TestLooksLikeDiff(t *testing.T) {
	if !looksLikeDiff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n") {
		t.Fatal("git diff should be detected")
	}
	if looksLikeDiff(`{"schema":"object"}`) {
		t.Fatal("json should not be a diff")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestDashboardEventsDrilldownByRefs(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "evt-secret", "secret_path", `{"path":"/workspace/.aws/credentials"}`)
	insertDashboardEvent(t, db, "evt-egress", "metadata_ip", `{"dst_ip":"169.254.169.254"}`)

	req := httptest.NewRequest("GET", "/api/events?run=run-dash&refs=runtime_event/evt-egress", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).events(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Total  int `json:"total"`
		Events []struct {
			ID        string `json:"id"`
			EventType string `json:"event_type"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || len(out.Events) != 1 || out.Events[0].ID != "evt-egress" {
		t.Fatalf("unexpected drilldown result: %+v", out)
	}
}

func TestDashboardEventsNetworkGroup(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "evt-dns", "private_cidr", `{"dst_ip":"127.0.0.53"}`)
	insertDashboardEvent(t, db, "evt-egress", "metadata_ip", `{"dst_ip":"169.254.169.254"}`)

	req := httptest.NewRequest("GET", "/api/events?run=run-dash&lens=network-egress&group=risky_egress", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).events(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Total  int `json:"total"`
		Events []struct {
			ID string `json:"id"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || out.Events[0].ID != "evt-egress" {
		t.Fatalf("risky egress should exclude loopback private_cidr: %+v", out)
	}
}

func newDashboardTestDB(t *testing.T) *sql.DB {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertDashboardEvent(t *testing.T, db *sql.DB, id, eventType, payload string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, correlation_method, correlation_confidence, pid, ppid, created_at)
		VALUES (?, 'run-dash', 'session-dash', 'tool-dash', 'proc-dash', 'agentprov_ebpf', ?, ?, 'container_time_window', 0.92, 4242, 4000, '2026-06-30T00:00:00Z')`,
		id, eventType, payload); err != nil {
		t.Fatal(err)
	}
}

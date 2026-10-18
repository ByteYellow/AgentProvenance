package daemon_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/aitools"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestAuditInterfacesShareReadOnlyContract(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	line := `type=SECCOMP msg=audit(1792342593.757:130): pid=42 comm="fixture" arch=c00000b7 syscall=203 code=0x7ffc0000`
	if _, err := telemetry.IngestAuditReader(ctx, db, telemetry.AuditIngestOptions{RunID: "run/one"}, strings.NewReader(line)); err != nil {
		t.Fatal(err)
	}
	before, err := telemetry.ListEvents(db, "run/one", "")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((daemon.Server{DB: db, AuthToken: "test-token"}).Handler())
	defer server.Close()
	client := daemon.NewClient(server.URL)
	client.Token = ""
	opts := telemetry.AuditAssociationOptions{RunID: "run/one", Limit: 1}
	if _, err := client.TelemetryAuditAssociations(ctx, opts); err == nil {
		t.Fatal("unauthenticated read accepted")
	}
	client.Token = "test-token"
	want, err := telemetry.BuildAuditAssociations(ctx, db, opts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.TelemetryAuditAssociations(ctx, opts)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatalf("client=%+v %v", got, err)
	}
	w := httptest.NewRecorder()
	(dashboard.Server{DB: db}).Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/audit/associations?run=run%2Fone&limit=1", nil))
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("dashboard=%s", w.Body.String())
	}
	tool, err := aitools.Dispatch(db, "get_audit_associations", map[string]any{"run": "run/one", "limit": float64(1)})
	if err != nil || !reflect.DeepEqual(tool, want) {
		t.Fatalf("tool=%+v %v", tool, err)
	}
	for _, in := range []map[string]any{{"run": "run/one", "limit": 1.5}, {"run": "run/one", "limit": true}, {"run": "run/one", "limit": "1"}, {"run": "run/one", "session": "s"}, {"run": 42}, {}} {
		if _, err := aitools.Dispatch(db, "get_audit_associations", in); !errors.Is(err, telemetry.ErrAuditAssociationQuery) {
			t.Fatalf("bad input accepted: %v %v", in, err)
		}
	}
	for _, tdef := range aitools.Catalog() {
		if tdef.Name == "get_audit_associations" && tdef.Writes {
			t.Fatal("audit query advertised as write tool")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := client.TelemetryAuditAssociations(canceled, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	req, _ := http.NewRequest("POST", server.URL+"/v1/telemetry/audit-associations?run=run%2Fone", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("write method returned %d", resp.StatusCode)
	}
	after, err := telemetry.ListEvents(db, "run/one", "")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read interfaces changed source evidence")
	}
}

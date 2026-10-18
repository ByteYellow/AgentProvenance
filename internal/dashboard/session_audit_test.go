package dashboard

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const sessionAuditRun = "ui-session-graph"

type sessionAuditFixture struct {
	db     *sql.DB
	worker string
	other  string
	audits []string
	entry  string
	result string
}

func newSessionAuditFixture(t *testing.T) sessionAuditFixture {
	t.Helper()
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	addSessionGraphFixture(t, svc)
	worker, err := svc.SessionGraphScope(context.Background(), sessionAuditRun, "codex", "worker")
	if err != nil {
		t.Fatal(err)
	}
	other, err := svc.SessionGraphScope(context.Background(), sessionAuditRun, "claude", "root")
	if err != nil {
		t.Fatal(err)
	}
	f := sessionAuditFixture{db: db, worker: worker.ToolIDs[0], other: other.ToolIDs[0], entry: "audit-attempt", result: "audit-result"}
	const boot = "01234567-89ab-cdef-0123-456789abcdef"
	const thread = boot + ":43:1000000000"
	stamp := time.Unix(1792342593, 757000000).UTC()
	for _, event := range []struct {
		id, kind, stage string
		offset          time.Duration
	}{
		{"audit-before", "execve", "", -5 * time.Millisecond},
		{f.entry, "file_open", "attempt", 100 * time.Microsecond},
		{f.result, "syscall_result", "result", 200 * time.Microsecond},
		{"audit-after", "execve", "", 5 * time.Millisecond},
	} {
		body := map[string]any{"host_id": "fixture-host", "boot_id": boot, "realtime_coarse_resolution_ns": 4000000,
			"process_instance_id": boot + ":42:1000000000", "process_start_ns": "1000000000", "monotonic_ns": strconv.FormatInt(int64(10*time.Second+event.offset), 10),
			"thread_instance_id": thread, "thread_start_ns": "1000000000", "tid": 43, "comm": "fixture", "path": "/fixture/private.txt"}
		if event.stage != "" {
			body["operation_id"], body["operation"], body["syscall_start_ns"] = "syscall-v1:"+thread+":42:1000000000:10000100000", "file_open", "10000100000"
			body["observation_stage"], body["syscall_number"], body["sensor_arch"] = event.stage, 56, "arm64"
		}
		if event.stage == "result" {
			body["syscall_result"], body["syscall_outcome"] = -13, "error"
		}
		raw, _ := json.Marshal(body)
		// The legacy scope intentionally has the same name as a different native
		// Session. Only the recorded tool edge below supplies Session membership.
		if _, err := db.Exec(`INSERT INTO events(id,run_id,pid,source,event_type,payload,created_at,session_id)
			VALUES(?,?,42,'agentprov_ebpf',?,?,?,'root')`, event.id, sessionAuditRun, event.kind, string(raw), stamp.Add(event.offset).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	f.link(t, f.entry, f.worker)
	lines := `type=AVC msg=audit(1792342593.757:130): apparmor="DENIED" operation="open" profile="fixture" pid=42 comm="fixture" name="/fixture/private.txt" requested_mask="r" denied_mask="r"
type=SECCOMP msg=audit(1792342593.757:131): pid=42 comm="fixture" arch=c00000b7 syscall=56 code=0x5000d
type=SECCOMP msg=audit(1792342593.757:132): pid=99 comm="unassigned" arch=c00000b7 syscall=56 code=0x7ffc0000
`
	if _, err := telemetry.IngestAuditReader(context.Background(), db, telemetry.AuditIngestOptions{RunID: sessionAuditRun, Source: telemetry.AuditSource{HostID: "fixture-host", BootID: boot}}, strings.NewReader(lines)); err != nil {
		t.Fatal(err)
	}
	report, err := telemetry.BuildAuditAssociations(context.Background(), db, telemetry.AuditAssociationOptions{RunID: sessionAuditRun})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range report.Items {
		if item.Operation.Status == "inferred" {
			f.audits = append(f.audits, item.EventID)
		}
	}
	if len(f.audits) != 2 {
		t.Fatalf("fixture associations: %+v", report)
	}
	return f
}

func (f sessionAuditFixture) link(t *testing.T, event, tool string) {
	t.Helper()
	if _, err := f.db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,source_event_id,created_at)
		VALUES(?,?,?,?,'agent_syscall',?,'2026-10-18T00:00:03Z')`, "session-audit-"+event+tool, sessionAuditRun, tool, "runtime_event/"+event, event); err != nil {
		t.Fatal(err)
	}
}

func sessionAuditSources(t *testing.T, server Server) map[string]SearchSource {
	t.Helper()
	result := map[string]SearchSource{}
	for cursor := ""; ; {
		page, err := server.SearchSources(context.Background(), SearchSourceOptions{RunID: sessionAuditRun, Harness: "codex", SessionID: "worker", Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range page.Sources {
			result[source.ID] = source
		}
		if !page.HasMore {
			return result
		}
		cursor = page.NextCursor
	}
}

func TestSessionAuditScopeUsesOperationsAndNativeContext(t *testing.T) {
	f := newSessionAuditFixture(t)
	server := Server{DB: f.db}
	ctx := context.Background()
	scope, err := server.sessionGraphScope(ctx, sessionAuditRun, "codex", "worker")
	if err != nil || scope.Audit == nil || scope.Audit.RelatedCount != 2 {
		t.Fatalf("scope: %+v %v", scope, err)
	}
	for _, id := range f.audits {
		if !slices.Contains(scope.EventIDs, id) || scope.AuditEvents[id].Status != "inferred" || !slices.Contains(scope.AuditEvents[id].EvidenceRefs, f.worker) {
			t.Fatalf("missing derived membership: %+v", scope)
		}
	}
	if slices.Contains(scope.EventIDs, f.result) || slices.Contains(scope.EventIDs, "audit-before") {
		t.Fatal("related support widened the selected raw evidence")
	}
	for _, session := range [][2]string{{"codex", "root"}, {"claude", "root"}, {"codex", "quiet"}} {
		other, err := server.sessionGraphScope(ctx, sessionAuditRun, session[0], session[1])
		if err != nil || len(other.AuditEvents) != 0 {
			t.Fatalf("legacy session or process promoted to native identity: %+v %v", other, err)
		}
	}
	sources := sessionAuditSources(t, server)
	for _, id := range f.audits {
		if source := sources["3/"+id]; source.SessionAssociation == nil || source.SessionAssociation.Rule != sessionAuditRule || source.SessionID != "" {
			t.Fatalf("search lost projection or rewrote ownership: %+v", source)
		}
	}
	for _, lang := range []string{"en", "zh-CN"} {
		base := "/api/lens?run=" + sessionAuditRun + "&harness=codex&session=worker&detail=raw&lang=" + lang
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, httptest.NewRequest("GET", base, nil))
		var lens provenance.GraphLensManifest
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &lens) != nil || lens.Query.SessionScope.Audit.RelatedCount != 2 {
			t.Fatalf("lens: %d %s", w.Code, w.Body.String())
		}
		for _, id := range f.audits {
			focused := httptest.NewRecorder()
			server.Handler().ServeHTTP(focused, httptest.NewRequest("GET", base+"&focus="+url.QueryEscape("runtime_event/"+id), nil))
			var view provenance.GraphLensManifest
			if focused.Code != 200 || json.Unmarshal(focused.Body.Bytes(), &view) != nil {
				t.Fatalf("audit focus: %d %s", focused.Code, focused.Body.String())
			}
			seen := false
			for _, node := range view.Nodes {
				if node.ID == "runtime_event/"+id && node.Data["session_association"] != nil {
					seen = true
				}
			}
			if !seen {
				t.Fatal("graph focus lost the inferred label")
			}
		}
		w = httptest.NewRecorder()
		server.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/events?run="+sessionAuditRun+"&harness=codex&session=worker&type=access_control&lang="+lang, nil))
		var events struct {
			Total               int
			Events              []telemetry.EventRecord
			SessionAudit        *provenance.SessionAuditScope              `json:"session_audit"`
			SessionAssociations map[string]provenance.SessionAuditRelation `json:"session_associations"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &events) != nil || events.Total != 2 || events.SessionAudit == nil || len(events.SessionAssociations) != 2 {
			t.Fatalf("event scope: %d %s", w.Code, w.Body.String())
		}
		for id, relation := range events.SessionAssociations {
			if !reflect.DeepEqual(relation, *sources["3/"+id].SessionAssociation) {
				t.Fatal("event and search scope metadata disagree")
			}
		}
	}
	var assigned int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM events WHERE source IN ('apparmor_audit','seccomp_audit') AND (COALESCE(session_id,'')!='' OR COALESCE(tool_call_id,'')!='' OR pid!=0)`).Scan(&assigned); err != nil || assigned != 0 {
		t.Fatalf("projection changed original audit: %d %v", assigned, err)
	}
}

func TestSessionAuditRejectsConflictingAndLateContext(t *testing.T) {
	for _, variant := range []string{"other_tool_edge", "other_tool_column", "missing_lifetime", "competing_operation", "cross_run_edge"} {
		t.Run(variant, func(t *testing.T) {
			f := newSessionAuditFixture(t)
			server := Server{DB: f.db}
			if _, err := server.sessionGraphScope(context.Background(), sessionAuditRun, "codex", "worker"); err != nil {
				t.Fatal(err)
			}
			var err error
			switch variant {
			case "other_tool_edge", "cross_run_edge":
				f.link(t, f.result, f.other)
				if variant == "cross_run_edge" {
					_, err = f.db.Exec(`UPDATE graph_edges SET run_id='other-run' WHERE id=?`, "session-audit-"+f.result+f.other)
				}
			case "other_tool_column":
				_, err = f.db.Exec(`UPDATE events SET tool_call_id=? WHERE id=?`, f.other, f.result)
			case "missing_lifetime":
				_, err = f.db.Exec(`UPDATE events SET payload=json_remove(payload,'$.process_instance_id') WHERE source='agentprov_ebpf'`)
			case "competing_operation":
				_, err = f.db.Exec(`INSERT INTO events(id,run_id,pid,source,event_type,payload,created_at)
				 SELECT 'audit-rival',run_id,pid,source,event_type,
				 json_set(payload,'$.operation_id',replace(json_extract(payload,'$.operation_id'),'10000100000','10000150000'),
				 '$.syscall_start_ns','10000150000','$.monotonic_ns','10000150000'),created_at FROM events WHERE id=?`, f.entry)
			}
			if err != nil {
				t.Fatal(err)
			}
			scope, err := server.sessionGraphScope(context.Background(), sessionAuditRun, "codex", "worker")
			want := 0
			if variant == "cross_run_edge" {
				want = 2
			}
			if err != nil || len(scope.AuditEvents) != want {
				t.Fatalf("scope did not re-evaluate late evidence: %+v %v", scope, err)
			}
		})
	}
}

func TestSessionAuditReplayFreezesMembershipAndExclusions(t *testing.T) {
	f := newSessionAuditFixture(t)
	server := Server{DB: f.db}
	ctx := context.Background()
	for _, name := range []string{"whole", "session", "excluded_anchor", "excluded_audit"} {
		t.Run(name, func(t *testing.T) {
			selection := ReplaySelection{RunID: sessionAuditRun, Scope: "session", Harness: "codex", SessionID: "worker"}
			if name == "whole" {
				selection = ReplaySelection{RunID: sessionAuditRun, Scope: "whole_run"}
			}
			if name == "excluded_anchor" {
				selection.ExcludeRecords = []string{"3/" + f.entry}
			}
			if name == "excluded_audit" {
				selection.ExcludeRecords = []string{"3/" + f.audits[0]}
			}
			p, err := server.PrepareSelectedOfflineReplay(ctx, selection)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if root := os.Getenv("AGENTPROV_SESSION_AUDIT_OUTPUT"); root != "" {
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				file, err := os.Create(filepath.Join(root, name+".zip"))
				if err != nil {
					t.Fatal(err)
				}
				writeErr := p.WriteZIP(ctx, file)
				closeErr := file.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("write fixture: %v %v", writeErr, closeErr)
				}
			}
			files, _ := replayZIPData(t, p)
			found := map[string]SearchSource{}
			encoded := strings.TrimSuffix(strings.TrimPrefix(string(files["assets/catalog.js"]), `window.AgentProvOfflineCatalog="`), `";`)
			raw, err := base64.StdEncoding.DecodeString(encoded)
			var catalog struct{ Runs map[string]ReplayRun }
			if err != nil || json.Unmarshal(raw, &catalog) != nil {
				t.Fatal("invalid replay catalog")
			}
			scopedEvents := catalog.Runs[sessionAuditRun].Sessions[`["codex","worker"]`].EventIDs
			for _, data := range files {
				var page SearchSources
				if json.Unmarshal(data, &page) == nil && page.SchemaVersion == "agentprovenance.search_sources/v1" && page.Harness == "codex" && page.SessionID == "worker" {
					for _, source := range page.Sources {
						found[source.ID] = source
					}
				}
			}
			for i, id := range f.audits {
				source, exists := found["3/"+id]
				if name == "excluded_audit" && i == 0 {
					if exists || slices.Contains(scopedEvents, id) {
						t.Fatal("excluded audit is still in scope")
					}
					continue
				}
				if !exists || source.SessionAssociation == nil || !slices.Contains(scopedEvents, id) {
					t.Fatalf("selected audit lost from frozen scope: %+v events=%v", source, scopedEvents)
				}
				if name == "whole" {
					want := sessionAuditSources(t, server)["3/"+id]
					if !reflect.DeepEqual(want, source) {
						t.Fatal("whole replay changed Session association")
					}
				} else if source.SessionAssociation.Status != "unavailable" || source.SessionAssociation.Reason != "replay_evidence_excluded" || len(source.SessionAssociation.EvidenceRefs) != 0 {
					t.Fatalf("excluded support still advertised: %+v", source)
				}
			}
		})
	}
	// A later rival is excluded from a whole-run share. The original complete
	// source still prevents the audit from acquiring a unique Session membership.
	if _, err := f.db.Exec(`INSERT INTO events(id,run_id,pid,source,event_type,payload,created_at)
	 SELECT 'excluded-rival',run_id,pid,source,event_type,
	 json_set(payload,'$.operation_id',replace(json_extract(payload,'$.operation_id'),'10000100000','10000150000'),
	 '$.syscall_start_ns','10000150000','$.monotonic_ns','10000150000'),created_at FROM events WHERE id=?`, f.entry); err != nil {
		t.Fatal(err)
	}
	p, err := server.PrepareSelectedOfflineReplay(ctx, ReplaySelection{RunID: sessionAuditRun, Scope: "whole_run", ExcludeRecords: []string{"3/excluded-rival"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	files, _ := replayZIPData(t, p)
	for _, data := range files {
		var page SearchSources
		if json.Unmarshal(data, &page) == nil && page.SchemaVersion == "agentprovenance.search_sources/v1" && page.SessionID != "" {
			for _, source := range page.Sources {
				if slices.Contains(f.audits, strings.TrimPrefix(source.ID, "3/")) {
					t.Fatal("excluded rival promoted ambiguous audit into a Session")
				}
			}
		}
	}
}

func TestSessionAuditSourcePagingAndEnglishMetadata(t *testing.T) {
	f := newSessionAuditFixture(t)
	// More than one catalog page; every record remains individually addressable.
	var lines strings.Builder
	for i := 200; i < 705; i++ {
		fmt.Fprintf(&lines, "type=SECCOMP msg=audit(1792342593.757:%d): pid=42 arch=c00000b7 syscall=56 code=0x5000d\n", i)
	}
	if _, err := telemetry.IngestAuditReader(context.Background(), f.db, telemetry.AuditIngestOptions{RunID: sessionAuditRun, Source: telemetry.AuditSource{HostID: "fixture-host", BootID: "01234567-89ab-cdef-0123-456789abcdef"}}, strings.NewReader(lines.String())); err != nil {
		t.Fatal(err)
	}
	handler := (Server{DB: f.db}).Handler()
	cursor, count := "", 0
	for {
		path := "/api/search/sources?run=" + sessionAuditRun + "&harness=codex&session=worker&cursor=" + url.QueryEscape(cursor)
		a, b := httptest.NewRecorder(), httptest.NewRecorder()
		handler.ServeHTTP(a, httptest.NewRequest("GET", path+"&lang=en", nil))
		handler.ServeHTTP(b, httptest.NewRequest("GET", path+"&lang=zh-CN", nil))
		if a.Code != 200 || a.Body.String() != b.Body.String() {
			t.Fatalf("localized API metadata: %d %s", a.Code, a.Body.String())
		}
		var page SearchSources
		if err := json.Unmarshal(a.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, source := range page.Sources {
			if source.SessionAssociation != nil {
				count++
			}
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if count != 507 {
		t.Fatalf("paged audit count=%d", count)
	}
}

func TestSessionAuditRuntimeLimitRetainsDirectScope(t *testing.T) {
	f := newSessionAuditFixture(t)
	if _, err := f.db.Exec(`WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<50001)
	 INSERT INTO events(id,run_id,pid,source,event_type,payload,created_at)
	 SELECT 'session-audit-load-'||n,?,42,'agentprov_ebpf','process_observed','{}','2026-10-18T00:00:00Z' FROM seq`, sessionAuditRun); err != nil {
		t.Fatal(err)
	}
	scope, err := (Server{DB: f.db}).sessionGraphScope(context.Background(), sessionAuditRun, "codex", "worker")
	if err != nil || scope.Audit == nil || scope.Audit.Status != "incomplete" || !slices.Contains(scope.Audit.Issues, "runtime_input_limit") || len(scope.AuditEvents) != 0 || !slices.Contains(scope.EventIDs, f.entry) {
		t.Fatalf("limit hidden or existing scope lost: %+v %v", scope, err)
	}
}

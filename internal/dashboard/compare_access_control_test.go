package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const comparisonStateFixture = `{"schema_version":"agentprovenance.access_control_state/v1","evidence_kind":"state_snapshot","source":"procfs","started_at":"2026-10-19T00:00:00Z","observed_at":"2026-10-19T00:00:00.01Z","identity":{"status":"observed","pid":42,"tid":43,"start_ticks":"100","cgroup_id":"5"},"apparmor":{"status":"observed","source":"attr/apparmor/current","label":"fixture (complain)","mode":"complain"},"seccomp":{"status":"observed","source":"status","mode_number":0,"mode":"disabled","filter_count":0,"no_new_privs":0}}`
const comparisonConfigFixture = `{"schema_version":"agentprovenance.access_control_config/v1","evidence_kind":"configuration_declaration","source":"k8s_api","pod_uid":"fixture-pod","container_name":"worker","declarations":[{"mechanism":"seccomp","evidence_kind":"configuration_declaration","status":"declared","source":"k8s_api:spec.securityContext.seccompProfile","resource_version":"77","observed_at":"2026-10-19T00:00:00Z","profile_type":"RuntimeDefault"},{"mechanism":"apparmor","evidence_kind":"configuration_declaration","status":"not_declared","source":"k8s_api:spec","observed_at":"2026-10-19T00:00:00Z"}]}`
const comparisonCollectionFixture = `{"schema_version":"agentprovenance.audit_collection/v1","evidence_kind":"collection_status","reader_id":"fixture-reader","source_path":"/fixture/audit.jsonl","mechanism":"all","raw_records_retained":false,"status":"waiting","reason":"source_drained","coverage_scope":"selected_source_file","upstream_loss":"unknown","observed_at":"2026-10-19T00:00:00Z","committed_offset":100,"pending_bytes":0,"read":1,"ingested":1,"duplicates":0,"skipped":0,"failed":0,"identity_incomplete":0,"batches":1}`

func addAccessComparisonFixture(t *testing.T, server Server, run string) {
	t.Helper()
	for _, f := range []struct{ id, kind, source, body string }{
		{"state", "access_control_state", "procfs_access_control", comparisonStateFixture},
		{"config", "access_control_config", "k8s", comparisonConfigFixture},
		{"collection", "access_control_collection", "audit_reader", comparisonCollectionFixture},
		{"file-result", "syscall_result", "agentprov_ebpf", `{"operation":"file_open","path":"/fixture/secret","syscall_result":-13,"syscall_outcome":"failure","errno":13,"operation_id":"private-operation","pid":42}`},
		{"connect-result", "syscall_result", "agentprov_ebpf", `{"operation":"network_connect","dst_ip":"192.0.2.1","dst_port":443,"syscall_result":0,"syscall_outcome":"success"}`},
		{"exit", "process_exit", "agentprov_ebpf", `{"comm":"fixture","exit_signal":31,"termination":"signal","exit_scope":"process"}`},
		{"thread", "thread_exit", "agentprov_ebpf", `{"comm":"fixture","exit_code":0,"termination":"exit","exit_scope":"thread"}`},
		{"combined", "secret_path", "agentprov_ebpf", `{"operation":"file_open","observation_stage":"attempt_and_result","path":"/fixture/combined","syscall_result":-13,"syscall_outcome":"failure","errno":13}`},
	} {
		if f.id == "state" || f.id == "file-result" {
			f.body = `{"payload":{"raw":` + f.body + `}}`
		}
		if _, err := server.DB.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES(?,?,?,?,?,?)`, run+"-"+f.id, run, f.source, f.kind, f.body, "2026-10-19T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	var lines strings.Builder
	for i := 0; i < 57; i++ {
		fmt.Fprintf(&lines, "type=SECCOMP msg=audit(1792342593.757:%d): pid=42 comm=\"fixture\" arch=c00000b7 syscall=203 code=0x7ffc0000\n", i+100)
	}
	lines.WriteString("type=SECCOMP msg=audit(1792342593.757:200): pid=42 arch=c00000b7 syscall=56 code=0x5000d\n")
	lines.WriteString("type=SECCOMP msg=audit(1792342593.757:201): pid=42 arch=c000003e syscall=257 code=0x80000000\n")
	lines.WriteString("type=AVC msg=audit(1792342593.757:202): apparmor=\"DENIED\" operation=\"open\" profile=\"fixture\" name=\"/fixture/secret\" pid=42 requested_mask=\"r\" denied_mask=\"r\"\n")
	lines.WriteString("type=AVC msg=audit(1792342593.757:203): apparmor=\"ALLOWED\" operation=\"open\" profile=\"fixture\" name=\"/fixture/secret\" pid=42 requested_mask=\"r\" denied_mask=\"r\"\n")
	if _, err := telemetry.IngestAuditReader(context.Background(), server.DB, telemetry.AuditIngestOptions{RunID: run, Source: telemetry.AuditSource{HostID: "fixture-host", BootID: "01234567-89ab-cdef-0123-456789abcdef"}}, strings.NewReader(lines.String())); err != nil {
		t.Fatal(err)
	}
}

func accessRows(page ComparisonPage) []ComparisonRecord {
	rows := []ComparisonRecord{}
	for _, r := range page.Records {
		if r.Dimension == "access_control" {
			rows = append(rows, r)
		}
	}
	return rows
}

func TestAccessComparisonEvidenceSemantics(t *testing.T) {
	_, db, _ := artifactStore(t)
	server := Server{DB: db}
	addAccessComparisonFixture(t, server, "access")
	db.SetMaxOpenConns(1)
	all := readComparison(t, server, "access")
	rows := accessRows(all)
	if len(rows) != 71 || len(all.Issues) != 0 {
		t.Fatalf("projection counts: rows=%d issues=%+v", len(rows), all.Issues)
	}
	counts := map[string]int{}
	var aa []ComparisonRecord
	for _, r := range rows {
		counts[r.EvidenceKind]++
		if r.ComparisonScope != "observed_set" || r.Value == nil || r.Partial || r.Evidence.Node == "" || r.Evidence.Category != "runtime" {
			t.Fatalf("projection contract: %+v", r)
		}
		if strings.Contains(r.Key, "fixture-boot") || strings.Contains(r.Value.Preview, "private-operation") || strings.Contains(r.Value.Preview, "observed_at") {
			t.Fatalf("volatile identity in compared values: %+v", r)
		}
		if r.EvidenceKind == "audit_decision" {
			if strings.Contains(r.Value.Preview, "syscall_result") || strings.Contains(r.Value.Preview, "outcome") || strings.Contains(r.Value.Preview, "termination") {
				t.Fatal("audit action manufactured runtime outcome")
			}
			if r.Mechanism == "apparmor" {
				aa = append(aa, r)
			} else if strings.Contains(r.Value.Preview, `"decision":"ERRNO"`) && !strings.Contains(r.Value.Preview, `"action_data":13`) {
				t.Fatal("ERRNO action data lost")
			}
		} else if slices.Contains([]string{"syscall_result", "process_exit", "thread_exit"}, r.EvidenceKind) && r.Mechanism != "" {
			t.Fatal("runtime failure attributed to an unobserved mechanism")
		}
		if r.EvidenceKind == "state_snapshot" && r.Mechanism == "seccomp" && !strings.Contains(r.Value.Preview, `"mode_number":0`) {
			t.Fatal("observed disabled state became unknown")
		}
		if r.EvidenceKind == "collection_status" && (!strings.Contains(r.Value.Preview, `"upstream_loss":"unknown"`) || !strings.Contains(r.Value.Preview, `"coverage_scope":"selected_source_file"`)) {
			t.Fatal("file coverage widened to whole kernel")
		}
	}
	if counts["audit_decision"] != 61 || counts["state_snapshot"] != 2 || counts["configuration_declaration"] != 2 || counts["syscall_result"] != 3 || counts["process_exit"] != 1 || counts["thread_exit"] != 1 {
		t.Fatalf("evidence categories conflated: %v", counts)
	}
	if len(aa) != 2 || aa[0].Key != aa[1].Key || aa[0].Value.SHA256 == aa[1].Value.SHA256 {
		t.Fatal("ALLOWED and DENIED must compare as distinct decisions for one observed operation")
	}
	combinedAttempts := 0
	for _, r := range all.Records {
		if r.Evidence.ID == "3/access-combined" && r.Dimension == "files" {
			combinedAttempts++
		}
	}
	if combinedAttempts != 1 {
		t.Fatal("combined result suppressed original attempt")
	}
	var responses []string
	for _, lang := range []string{"en", "zh-CN"} {
		var text strings.Builder
		cursor := ""
		for {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/api/compare/records?run=access&lang="+lang+"&cursor="+url.QueryEscape(cursor), nil)
			r.Header.Set("Accept-Language", lang)
			server.Handler().ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			text.Write(w.Body.Bytes())
			var page ComparisonPage
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if !page.HasMore {
				break
			}
			cursor = page.NextCursor
		}
		responses = append(responses, text.String())
	}
	if responses[0] != responses[1] || !strings.Contains(responses[0], `"dimension":"access_control"`) {
		t.Fatal("API output localized")
	}
}

func TestAccessComparisonStableIdentityAndIncompleteEvidence(t *testing.T) {
	project := func(kind, source, text string) ([]ComparisonRecord, []ComparisonIssue) {
		t.Helper()
		var payload map[string]any
		if err := decodeComparisonJSON([]byte(text), &payload); err != nil {
			t.Fatal(err)
		}
		return comparisonAccessControl(SearchSource{ID: "fixture", Kind: kind, SourceID: source}, payload)
	}
	for _, tc := range []struct{ kind, source, body string }{
		{"access_control_state", "procfs_access_control", comparisonStateFixture},
		{"access_control_config", "k8s", comparisonConfigFixture},
	} {
		a, ai := project(tc.kind, tc.source, tc.body)
		changed := strings.NewReplacer(`"pid":42`, `"pid":99`, `"tid":43`, `"tid":100`, `"start_ticks":"100"`, `"start_ticks":"200"`, `"resource_version":"77"`, `"resource_version":"100"`, "2026-10-19", "2026-10-20", "fixture-pod", "new-pod").Replace(tc.body)
		b, bi := project(tc.kind, tc.source, changed)
		if len(a) == 0 || !reflect.DeepEqual(a, b) || len(ai)+len(bi) != 0 {
			t.Fatalf("volatile metadata changed comparison: %s", tc.kind)
		}
	}
	for _, tc := range []struct{ name, kind, source, body string }{
		{"state unavailable", "access_control_state", "procfs_access_control", strings.Replace(comparisonStateFixture, `{"status":"observed","source":"attr/apparmor/current","label":"fixture (complain)","mode":"complain"}`, `{"status":"unavailable","reason":"permission_denied"}`, 1)},
		{"pending file", "access_control_collection", "audit_reader", strings.Replace(comparisonCollectionFixture, `"pending_bytes":0`, `"pending_bytes":100`, 1)},
		{"target absent", "syscall_result", "agentprov_ebpf", `{"operation":"file_open","syscall_result":-1}`},
		{"host absent", "syscall_result", "agentprov_ebpf", `{"operation":"network_connect","dst_port":443,"syscall_result":-1}`},
		{"profile absent", "access_control_config", "k8s", strings.Replace(comparisonConfigFixture, `"profile_type":"RuntimeDefault"`, `"profile_type":""`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, issues := project(tc.kind, tc.source, tc.body)
			if len(issues) == 0 || len(rows) == 0 || !rows[0].Partial {
				t.Fatalf("missing data became complete: %+v %+v", rows, issues)
			}
		})
	}
	for _, tc := range []struct{ kind, source, body string }{
		{"access_control", "apparmor_audit", `{"schema_version":"unsupported"}`},
		{"access_control_state", "untrusted_source", comparisonStateFixture},
		{"access_control_config", "k8s", `{"declarations":[]}`},
		{"access_control_collection", "audit_reader", strings.Replace(comparisonCollectionFixture, `"upstream_loss":"unknown"`, `"upstream_loss":"0"`, 1)},
		{"syscall_result", "agentprov_ebpf", `{"operation":"file_open","syscall_result":1.5}`},
		{"process_exit", "agentprov_ebpf", `{}`},
		{"process_exit", "agentprov_ebpf", `{"exit_code":1.5}`},
	} {
		rows, issues := project(tc.kind, tc.source, tc.body)
		if len(rows) != 0 || len(issues) == 0 {
			t.Fatalf("invalid evidence accepted: %s %+v %+v", tc.kind, rows, issues)
		}
	}
	var config map[string]any
	if err := decodeComparisonJSON([]byte(comparisonConfigFixture), &config); err != nil {
		t.Fatal(err)
	}
	declaration := config["declarations"].([]any)[0]
	items := make([]any, 65)
	for i := range items {
		items[i] = declaration
	}
	config["declarations"] = items
	rows, issues := comparisonAccessControl(SearchSource{Kind: "access_control_config", SourceID: "k8s"}, config)
	if len(rows) != 64 || len(issues) != 1 || issues[0].Code != "access_control_declaration_limit" {
		t.Fatal("configuration projection exceeded its bound")
	}
	for _, r := range rows {
		if !r.Partial {
			t.Fatal("limited declarations presented as complete")
		}
	}
	rows, issues = project("syscall_result", "agentprov_ebpf", `{"operation":"file_open","path":"/fixture/\u5bc6\u94a5","syscall_result":-13}`)
	if len(rows) != 1 || len(issues) != 0 || !strings.Contains(rows[0].Label, "/fixture/\u5bc6\u94a5") {
		t.Fatal("original evidence language changed")
	}
}

func TestAccessInvestigationScopeAndFrozenReplay(t *testing.T) {
	paths, db, _ := artifactStore(t)
	server := Server{DB: db}
	addSessionGraphFixture(t, agentcontext.Service{DB: db, Paths: paths})
	const run = "ui-session-graph"
	addAccessComparisonFixture(t, server, run)
	addAccessComparisonFixture(t, server, "foreign-run")
	want := accessRows(readComparison(t, server, run))
	scope, err := (agentcontext.Service{DB: db}).SessionGraphScope(context.Background(), run, "codex", "worker")
	if err != nil {
		t.Fatal(err)
	}
	// A result with an explicit tool edge belongs to the session. Logged PID
	// equality never enrolls the independent audit/configuration/state records.
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at) VALUES('access-result-link',?,?,?,'agent_syscall','2026-10-19T00:00:00Z')`, run, scope.ToolIDs[0], "runtime_event/"+run+"-file-result"); err != nil {
		t.Fatal(err)
	}
	for _, selection := range []ReplaySelection{
		{RunID: run, Scope: "whole_run"},
		{RunID: run, Scope: "whole_run", ExcludeRecords: []string{"3/" + run + "-config", "3/" + run + "-state"}},
		{RunID: run, Scope: "session", Harness: "codex", SessionID: "worker"},
	} {
		t.Run(selection.Scope+fmt.Sprint(len(selection.ExcludeRecords)), func(t *testing.T) {
			p, err := server.PrepareSelectedOfflineReplay(context.Background(), selection)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			files, _ := replayZIPData(t, p)
			found := []ComparisonRecord{}
			for _, data := range files {
				var page ComparisonPage
				if json.Unmarshal(data, &page) == nil && page.SchemaVersion == "agentprovenance.comparison_records/v1" {
					if page.RunID != run {
						t.Fatal("foreign run exported")
					}
					found = append(found, accessRows(page)...)
				}
			}
			included := map[string]bool{}
			cursor := ""
			for {
				page, err := server.SearchSources(context.Background(), SearchSourceOptions{RunID: run, Harness: selection.Harness, SessionID: selection.SessionID, Cursor: cursor})
				if err != nil {
					t.Fatal(err)
				}
				for _, source := range page.Sources {
					if !slices.Contains(selection.ExcludeRecords, source.ID) {
						included[source.ID] = true
					}
				}
				if !page.HasMore {
					break
				}
				cursor = page.NextCursor
			}
			expected := []ComparisonRecord{}
			for _, r := range want {
				if included[r.Evidence.ID] {
					expected = append(expected, r)
				}
			}
			order := func(a, b ComparisonRecord) int { return strings.Compare(a.Key+a.Evidence.ID, b.Key+b.Evidence.ID) }
			slices.SortFunc(found, order)
			slices.SortFunc(expected, order)
			if !reflect.DeepEqual(found, expected) {
				t.Fatalf("search/selection/comparison differed: got %d expected %d", len(found), len(expected))
			}
			if selection.Scope == "session" && (len(found) != 1 || found[0].EvidenceKind != "syscall_result") {
				t.Fatal("unassigned access-control evidence entered a session")
			}
		})
	}
}

// Reuse recorded kernel captures without rerunning workloads or changing host
// security policy. The synthetic suite above runs on every platform by default.
func TestRecordedAccessComparisonReplay(t *testing.T) {
	directory := os.Getenv("AGENTPROV_AUDIT_COMPARISON_EVIDENCE")
	if directory == "" {
		t.Skip("set AGENTPROV_AUDIT_COMPARISON_EVIDENCE to recorded audit/runtime JSONL files")
	}
	for _, mechanism := range []string{"apparmor", "seccomp"} {
		t.Run(mechanism, func(t *testing.T) {
			_, db, _ := artifactStore(t)
			server := Server{DB: db}
			run := "recorded-" + mechanism
			f, err := os.Open(filepath.Join(directory, mechanism+"-runtime.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			result, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{Format: "auto", RunID: run}, f)
			f.Close()
			if err != nil || result.Ingested == 0 || result.Failed != 0 {
				t.Fatalf("runtime import: %+v %v", result, err)
			}
			f, err = os.Open(filepath.Join(directory, mechanism+"-journal.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			audit, err := telemetry.IngestAuditReader(context.Background(), db, telemetry.AuditIngestOptions{RunID: run, RetainRaw: true}, f)
			f.Close()
			if err != nil || audit.Ingested != 2 || audit.Failed != 0 {
				t.Fatalf("audit import: %+v %v", audit, err)
			}
			page := readComparison(t, server, run)
			rows := accessRows(page)
			decisions, outcomes := 0, 0
			for _, row := range rows {
				if row.EvidenceKind == "audit_decision" {
					decisions++
					if row.Mechanism != mechanism || strings.Contains(row.Value.Preview, "syscall_result") {
						t.Fatal("recorded audit semantics changed")
					}
				}
				if row.EvidenceKind == "syscall_result" || row.EvidenceKind == "process_exit" {
					outcomes++
				}
			}
			if decisions != 2 || outcomes == 0 {
				t.Fatalf("recorded decisions/outcomes absent: %d %d", decisions, outcomes)
			}
			p, err := server.PrepareOfflineReplay(context.Background(), run)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			files, _ := replayZIPData(t, p)
			frozen := []ComparisonRecord{}
			for _, data := range files {
				var saved ComparisonPage
				if json.Unmarshal(data, &saved) == nil && saved.SchemaVersion == "agentprovenance.comparison_records/v1" {
					frozen = append(frozen, accessRows(saved)...)
				}
			}
			order := func(a, b ComparisonRecord) int { return strings.Compare(a.Key+a.Evidence.ID, b.Key+b.Evidence.ID) }
			slices.SortFunc(rows, order)
			slices.SortFunc(frozen, order)
			if !reflect.DeepEqual(rows, frozen) {
				t.Fatal("recorded comparison changed in frozen replay")
			}
			if output := os.Getenv("AGENTPROV_AUDIT_COMPARISON_OUTPUT"); output != "" {
				if err := os.MkdirAll(output, 0700); err != nil {
					t.Fatal(err)
				}
				file, err := os.Create(filepath.Join(output, mechanism+".zip"))
				if err != nil {
					t.Fatal(err)
				}
				writeErr := p.WriteZIP(context.Background(), file)
				closeErr := file.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("export fixture: %v %v", writeErr, closeErr)
				}
			}
			t.Logf("recorded %s: runtime=%d audit=%d comparison=%d issues=%d; frozen comparison identical", mechanism, result.Ingested, audit.Ingested, len(rows), len(page.Issues))
		})
	}
}

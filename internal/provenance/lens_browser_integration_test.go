package provenance_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/browserlink"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const browserLayerRun = "browser-layered"

func browserLayerStore(t *testing.T) (store.Paths, *sql.DB) {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return paths, db
}

func browserLayerFixture(t *testing.T, paths store.Paths, db *sql.DB) []agentcontext.Entry {
	t.Helper()
	input := `{"type":"browser_session","schema_version":"agentprovenance.browser_capture/v1","producer_id":"p","namespace":"n","instance_id":"i","generation":"g","browser_id":"b","context_id":"c"}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"start","kind":"action_start","target_id":"page","target_type":"page","cdp_session_id":"cdp","operation_id":"op","operation":"navigate","payload":{"url":"https://example.test/"}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"end","kind":"action_end","target_id":"page","target_type":"page","cdp_session_id":"cdp","operation_id":"op","operation":"navigate","request_id":"req","frame_id":"frame","loader_id":"loader","payload":{"url":"https://example.test/"}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"frame","kind":"frame","target_id":"page","target_type":"page","cdp_session_id":"cdp","frame_id":"frame","loader_id":"loader","payload":{"url":"https://example.test/"}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"request","kind":"request","target_id":"page","target_type":"page","cdp_session_id":"cdp","request_id":"req","frame_id":"frame","loader_id":"loader","payload":{"url":"https://example.test/","method":"GET"}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"response","kind":"response","target_id":"page","target_type":"page","cdp_session_id":"cdp","request_id":"req","frame_id":"frame","loader_id":"loader","payload":{"status":200,"from_service_worker":true}}
`
	ctx := context.Background()
	parsed, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "browser", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	svc := agentcontext.Service{DB: db, Paths: paths}
	if _, err := svc.Save(ctx, browserLayerRun, parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	if _, err := hooksbridge.IngestContext(ctx, db, paths, browserLayerRun); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: browserLayerRun})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 6 {
		t.Fatalf("parser fixture total entries=%d, want one session plus five observations", len(page.Entries))
	}
	var entries []agentcontext.Entry
	for _, e := range page.Entries {
		if e.Browser != nil && e.Browser.EventID != "" {
			entries = append(entries, e)
		}
	}
	if len(entries) != 5 {
		t.Fatalf("parser fixture observations=%d", len(entries))
	}
	return entries
}

func browserLayerEdges(m provenance.GraphLensManifest) []provenance.GraphLensEdge {
	var result []provenance.GraphLensEdge
	for _, edge := range m.DerivedEdges {
		if strings.HasPrefix(edge.DerivationRule, "agentprov.browser_") {
			result = append(result, edge)
		}
	}
	return result
}

func TestBrowserLayerGraphBundleAndReplay(t *testing.T) {
	paths, db := browserLayerStore(t)
	entries := browserLayerFixture(t, paths, db)
	opts := provenance.GraphLensOptions{RunID: browserLayerRun, Lens: "default", Detail: "raw", Limit: 1000}
	online, err := provenance.BuildGraphLens(db, opts)
	if err != nil {
		t.Fatal(err)
	}
	edges := browserLayerEdges(online)
	if len(edges) != 10 {
		t.Fatalf("layered graph edges=%d: %+v", len(edges), edges)
	}
	refs := map[string]bool{}
	for _, entry := range entries {
		refs[entry.ObjectHash] = true
	}
	for _, edge := range edges {
		if edge.DerivationRule != browserlink.NativeRule || edge.Data["status"] != "supported" || edge.Data["basis"] != "explicit_reference" {
			t.Fatalf("missing metadata: %+v", edge)
		}
		for _, ref := range edge.EvidenceRefs {
			if !refs[ref] {
				t.Fatalf("invented source reference: %s", ref)
			}
		}
	}
	replay, err := provenance.BuildReplayLenses(db, browserLayerRun)
	if err != nil {
		t.Fatal(err)
	}
	if got := browserLayerEdges(replay.Views["default/raw"].Manifest); !reflect.DeepEqual(edges, got) {
		t.Fatal("online and replay rule output differs")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle(browserLayerRun)
	if err != nil {
		t.Fatal(err)
	}
	fresh, imported := browserLayerStore(t)
	if _, err := (forensics.Service{DB: imported, Paths: fresh}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-offline"); err != nil {
		t.Fatal(err)
	}
	offline, err := provenance.BuildGraphLens(imported, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := browserLayerEdges(offline); !reflect.DeepEqual(edges, got) {
		t.Fatal("Bundle import changed source refs or rule output")
	}
	opts.SessionScope = &provenance.GraphSessionScope{Harness: "browser", SessionID: "unrelated"}
	unrelated, err := provenance.BuildGraphLens(imported, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(browserLayerEdges(unrelated)) != 0 {
		t.Fatal("browser evidence leaked to unrelated session query")
	}
}

func TestBrowserLayerRuntimeQueryRequiresExternalCustody(t *testing.T) {
	paths, db := browserLayerStore(t)
	entries := browserLayerFixture(t, paths, db)
	const instance = "11111111-1111-4111-8111-111111111111:42:100"
	payload := `{"runtime_process_identity":"agentprov.runtime_process/v3","host_id":"host","process_instance_id":"` + instance + `","path":"/tmp/download"}`
	if _, err := db.Exec(`INSERT INTO events(id,run_id,pid,source,event_type,payload,created_at) VALUES ('file',?,42,'agentprov_ebpf','file_write',?,'2026-11-16T00:00:00Z')`, browserLayerRun, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,source_event_id,created_at) VALUES ('file-edge',?,'runtime_event/file','workspace_file//tmp/download','runtime_event_file','file','2026-11-16T00:00:00Z')`, browserLayerRun); err != nil {
		t.Fatal(err)
	}
	opts := provenance.GraphLensOptions{RunID: browserLayerRun, Detail: "raw", Limit: 1000}
	custody := []browserlink.RuntimeCustody{{RunID: browserLayerRun, Scope: browserlink.Scope{ProducerID: "p", Namespace: "n", InstanceID: "i", Generation: "g", BrowserID: "b", ContextID: "c"}, Role: "browser", HostID: "host", PID: 42, ProcessInstanceID: instance, SourceRefs: []string{entries[0].ObjectHash}}}
	with, err := provenance.BuildGraphLensWithBrowserCustody(db, opts, custody)
	if err != nil {
		t.Fatal(err)
	}
	count := func(m provenance.GraphLensManifest) int {
		n := 0
		for _, e := range m.DerivedEdges {
			if e.DerivationRule == browserlink.RuntimeRule {
				n++
			}
		}
		return n
	}
	if count(with) != 2 {
		t.Fatalf("runtime edges missing: %+v", with.DerivedEdges)
	}
	plain, err := provenance.BuildGraphLens(db, opts)
	if err != nil || count(plain) != 0 {
		t.Fatalf("default query granted runtime custody: %v", err)
	}
	replay, err := provenance.BuildSessionReplayLensesWithBrowserCustody(db, browserLayerRun, nil, custody)
	if err != nil || !reflect.DeepEqual(browserLayerEdges(with), browserLayerEdges(replay.Views["default/raw"].Manifest)) {
		t.Fatalf("runtime query/replay mismatch: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM agent_context_entries WHERE run_id=? AND object_hash=?`, browserLayerRun, entries[0].ObjectHash); err != nil {
		t.Fatal(err)
	}
	without, err := provenance.BuildGraphLensWithBrowserCustody(db, opts, custody)
	if err != nil || count(without) != 0 {
		t.Fatalf("excluded custody evidence kept runtime relation: %v", err)
	}
}

func TestBrowserLayerSessionLimitAfterSelection(t *testing.T) {
	paths, db := browserLayerStore(t)
	entries := browserLayerFixture(t, paths, db)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO agent_context_entries(id,run_id,source_id,session_id,source_key,source_sequence,kind,object_hash,parser_version,created_at)
		VALUES (?,?,'unselected-source','unselected-session',?,1,'message','0-unselected-object','chromium-cdp/v1','2026-11-16T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < browserlink.MaxRecords+1; i++ {
		id := fmt.Sprintf("unselected-%d", i)
		if _, err := stmt.Exec(id, browserLayerRun, id); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []*provenance.GraphSessionScope{
		{Harness: "browser", SessionID: entries[0].Source.SessionID},
		{SourceIDs: []string{entries[0].Source.ID}},
	} {
		m, err := provenance.BuildGraphLens(db, provenance.GraphLensOptions{RunID: browserLayerRun, Detail: "raw", Limit: 1000, SessionScope: scope})
		if err != nil {
			t.Fatal(err)
		}
		if len(browserLayerEdges(m)) != 10 {
			t.Fatalf("unselected records starved selected session: %+v", browserLayerEdges(m))
		}
		r, err := provenance.BuildSessionReplayLenses(db, browserLayerRun, scope)
		if err != nil || len(browserLayerEdges(r.Views["default/raw"].Manifest)) != 10 {
			t.Fatalf("session replay truncated silently: %v", err)
		}
	}
	if _, err := provenance.BuildGraphLens(db, provenance.GraphLensOptions{RunID: browserLayerRun}); err == nil || !strings.Contains(err.Error(), "record limit") {
		t.Fatalf("whole run overflow must fail explicitly: %v", err)
	}
}

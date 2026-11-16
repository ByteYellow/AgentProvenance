package provenance_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/browserlink"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const browserRevisionPrefix = `{"type":"browser_session","schema_version":"agentprovenance.browser_capture/v1","producer_id":"p","namespace":"n","instance_id":"i","generation":"g","browser_id":"b","context_id":"c"}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"start","kind":"action_start","target_id":"page","target_type":"page","cdp_session_id":"cdp","operation_id":"op","operation":"navigate","payload":{}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"request","kind":"request","target_id":"page","target_type":"page","cdp_session_id":"cdp","request_id":"req","payload":{}}
`

const browserRevisionSuffix = `{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"end","kind":"action_end","target_id":"page","target_type":"page","cdp_session_id":"cdp","operation_id":"op","operation":"navigate","request_id":"req","payload":{}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"response","kind":"response","target_id":"page","target_type":"page","cdp_session_id":"cdp","request_id":"req","payload":{"status":200}}
`

func TestBrowserLayerLatestRevisionAfterManifestAdvance(t *testing.T) {
	paths, db := browserLayerStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	ctx := context.Background()
	for index, input := range []string{browserRevisionPrefix, browserRevisionPrefix + browserRevisionSuffix} {
		// OwnedBrowserCapture.ParsedCaptures supplies this source evidence for
		// every sealed prefix; changing the approved pin creates new revisions.
		parsed, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "browser", Binding: "exact",
			BindingEvidence: []string{agentcontext.BrowserLocalOperatorEvidence, "browser_owned_manifest:sha256:" + strings.Repeat(fmt.Sprint(index), 64)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Save(ctx, browserLayerRun, parsed.Source, parsed.Records, parsed.Coverage); err != nil {
			t.Fatal(err)
		}
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: browserLayerRun})
	if err != nil || len(page.Entries) != 5 {
		t.Fatalf("latest entry fixture: count=%d err=%v", len(page.Entries), err)
	}
	history, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: browserLayerRun, IncludeRevisions: true})
	if err != nil || len(history.Entries) != 8 {
		t.Fatalf("fixture did not retain immutable revisions: count=%d err=%v", len(history.Entries), err)
	}
	current := map[string]bool{}
	for _, entry := range page.Entries {
		current[entry.ObjectHash] = true
	}
	for _, scope := range []*provenance.GraphSessionScope{nil, {Harness: "browser", SessionID: page.Entries[0].Source.SessionID}} {
		graph, err := provenance.BuildGraphLens(db, provenance.GraphLensOptions{RunID: browserLayerRun, Detail: "raw", Limit: 1000, SessionScope: scope})
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int{}
		for _, edge := range browserLayerEdges(graph) {
			counts[edge.EdgeType]++
			for _, ref := range edge.EvidenceRefs {
				if !current[ref] {
					t.Errorf("superseded revision retained as support: %s", edge.EdgeType)
				}
			}
		}
		if counts["browser_action_result"] != 1 || counts["browser_action_request"] != 1 || counts["browser_request_lifecycle"] != 1 {
			t.Errorf("manifest advance lost native relations: action_result=%d action_request=%d lifecycle=%d; want=1 each",
				counts["browser_action_result"], counts["browser_action_request"], counts["browser_request_lifecycle"])
		}
	}
}

func TestBrowserLayerRevisionLimitAfterLatestSelection(t *testing.T) {
	paths, db := browserLayerStore(t)
	entries := browserLayerFixture(t, paths, db)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO agent_context_entries(id,run_id,source_id,session_id,source_key,source_sequence,source_ordinal,kind,object_hash,parser_version,created_at)
		VALUES (?,?,?,?,?,0,?,?,'superseded-unread-object',?,'2026-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= browserlink.MaxRecords; i++ {
		entry := entries[0]
		if _, err := stmt.Exec(fmt.Sprintf("old-browser-revision-%d", i), browserLayerRun, entry.Source.ID,
			entry.Source.SessionID, entry.SourceKey, entry.SourceOrdinal, entry.Kind, entry.Source.ParserVersion); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	graph, err := provenance.BuildGraphLens(db, provenance.GraphLensOptions{RunID: browserLayerRun, Detail: "raw", Limit: 1000})
	if err != nil {
		t.Fatalf("superseded revisions consumed current record budget: %v", err)
	}
	if got := len(browserLayerEdges(graph)); got != 10 {
		t.Fatalf("latest native graph edges=%d want=10", got)
	}
}

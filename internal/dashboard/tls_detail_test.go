package dashboard

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// Both graph objects and runtime events describe the same saved capture. The
// fixture includes a long complete message to separate paging from capture loss.
func addTLSDetailFixture(t *testing.T, db *sql.DB, paths store.Paths) map[string]string {
	t.Helper()
	refs := map[string]string{}
	for _, name := range []string{"fragment", "complete", "binary", "historical", "checkpoint"} {
		capture := map[string]any{"rule": "agentprov.tls_reassembly/v3", "state": "incomplete", "reason": "capture_limit", "data_kind": "tls_fragment",
			"position": map[string]any{"stream_id": "18446744073709551614", "call_sequence": "9007199254740993", "offset": 256, "total_bytes": 8192}}
		body := "PUBLIC-TLS-FRAGMENT <img src=x onerror=alert(1)>"
		payload := map[string]any{"direction": "request", "capture": capture, "truncated": true, "fixture": true}
		switch name {
		case "complete":
			capture["state"], capture["reason"], capture["data_kind"] = "complete", "", "http_body"
			delete(capture, "position")
			payload["truncated"] = false
			body = strings.Repeat("PUBLIC-TLS-COMPLETE\n", 4000) + "COMPLETE-TAIL"
		case "binary":
			capture["reason"], capture["data_kind"] = "hpack_decode_failed", "hpack_fragment"
			payload["content_encoding"] = "base64"
			body = "AP8Q"
		case "historical":
			delete(payload, "capture")
			delete(payload, "truncated")
			body = "PUBLIC-HISTORICAL-TLS"
		case "checkpoint":
			capture["reason"] = "tls_call_sequence"
			capture["position"] = map[string]any{"stream_id": "17", "call_sequence": "3", "offset": 0, "total_bytes": 0, "checkpoint": true}
			body = ""
		}
		payload["content"] = body
		obj, err := (provenance.ObjectStore{DB: db, Paths: paths}).PutExternalObject(provenance.ExternalObjectInput{
			RunID: "ui-tls", Type: "llm_message", SourceID: "llm_request/ui-tls-" + name, Payload: payload,
		})
		if err != nil {
			t.Fatal(err)
		}
		refs[name] = obj.Hash
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at)
			VALUES (?,'ui-tls','agentprov_ebpf','tls_write',?,'2026-11-06T01:00:00Z')`, "ui-tls-"+name, string(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,source_event_id,created_at)
			VALUES (?,'ui-tls',?,?,'llm_body',?,'2026-11-06T01:00:00Z')`, "ui-tls-edge-"+name, "runtime_event/ui-tls-"+name, obj.Hash, "ui-tls-"+name); err != nil {
			t.Fatal(err)
		}
	}
	return refs
}

func TestTLSIncompletePreviewDoesNotPresentStaleIntent(t *testing.T) {
	input := []byte(`{"type":"llm_message","payload":{"direction":"response","model":"untrusted-summary","content":"PUBLIC-RETAINED-BYTES","capture":{"state":"incomplete","reason":"capture_limit","data_kind":"tls_fragment"},"semantics":{"tool_commands":["INVENTED-DECISION"]}}}`)
	body, ok := renderLLMMessage(input)
	if !ok || !strings.Contains(string(body), "PUBLIC-RETAINED-BYTES") || strings.Contains(string(body), "INVENTED-DECISION") || strings.Contains(string(body), "untrusted-summary") || !strings.Contains(string(body), "Retained fragment") {
		t.Fatalf("incomplete preview promoted semantics or lost retained bytes: %s", body)
	}
}

func TestTLSDetailMetadataInArtifactsGraphAndReplay(t *testing.T) {
	paths, db, _ := artifactStore(t)
	refs := addTLSDetailFixture(t, db, paths)
	s := Server{DB: db}
	read := func(node, mode, lang, offset string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		s.artifact(w, httptest.NewRequest("GET", "/api/artifact?run=ui-tls&node="+url.QueryEscape(node)+"&mode="+mode+"&view_lang="+lang+"&offset="+offset, nil))
		var out map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("artifact: %d %s", w.Code, w.Body.String())
		}
		return out
	}
	live := map[string]map[string]any{}
	for name, ref := range refs {
		for _, node := range []string{ref, "runtime_event/ui-tls-" + name} {
			for _, mode := range []string{"body", "raw"} {
				out := read(node, mode, "en", "0")
				meta, ok := out["tls"].(map[string]any)
				if !ok {
					t.Fatalf("TLS metadata missing: %s %s", node, mode)
				}
				if !reflect.DeepEqual(meta, read(node, mode, "zh-CN", "0")["tls"]) {
					t.Fatal("language changed machine capture metadata")
				}
				if name == "historical" {
					if meta["capture"] != nil {
						t.Fatal("invented completeness for historical evidence")
					}
				} else if (name == "complete") == (meta["truncated"] == true) {
					t.Fatalf("capture truncation mixed with paging: %+v", out)
				}
				live["en/"+mode+"/"+node] = out
			}
		}
	}
	page := read(refs["complete"], "body", "en", "65536")
	if page["has_more"] != false || !strings.Contains(page["content"].(string), "COMPLETE-TAIL") || page["tls"].(map[string]any)["truncated"] != false {
		t.Fatalf("paged complete body: %+v", page)
	}
	graph, err := provenance.BuildGraphLens(db, provenance.GraphLensOptions{RunID: "ui-tls", Lens: "default", Detail: "raw"})
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, node := range graph.Nodes {
		if node.ID == "runtime_event/ui-tls-fragment" {
			seen = true
			if node.Data["capture"] == nil || node.Data["truncated"] != true {
				t.Fatalf("runtime graph lost capture metadata: %+v", node)
			}
		}
	}
	if !seen {
		t.Fatal("runtime fragment absent from graph")
	}
	root := t.TempDir()
	replay, err := s.ExportReplay(context.Background(), "ui-tls", &staticdata.Writer{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	decode := func(ref staticdata.Ref, out any) {
		t.Helper()
		f, err := os.Open(filepath.Join(root, ref.Path))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		if err := json.NewDecoder(gz).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	var artifacts map[string]ReplayPages
	decode(replay.Artifacts, &artifacts)
	for key, want := range live {
		pages := artifacts[key]
		if len(pages.Pages) == 0 {
			t.Fatalf("missing replay content %s", key)
		}
		var got map[string]any
		decode(pages.Pages[0], &got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("replay changed %s", key)
		}
	}
}

//go:build linux || darwin

package cli

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/browsercustody"
	"github.com/byteyellow/agentprovenance/internal/browserlink"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type custodyFixture struct {
	root, config, receiver, receipts string
	cfg                              browsercustody.Config
	db                               *sql.DB
	support                          agentcontext.Entry
}

func newCustodyFixture(t *testing.T, capture string) custodyFixture {
	t.Helper()
	t.Setenv("AGENTPROV_DAEMON_URL", "")
	receiver, receipts, b01 := browserCLIFixture(t)
	root := t.TempDir()
	if out, err := runContextCLI(t, root, "import", "--run", "run", "--harness", "browser", "--browser-owned-config", receiver, "--browser-receipts", receipts, "--capture", capture); err != nil {
		t.Fatalf("B01 fixture import: %s %v", out, err)
	}
	raw, err := os.ReadFile(receipts)
	if err != nil {
		t.Fatal(err)
	}
	var list []agentcontext.BrowserReceipt
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	cfg := browsercustody.Config{SchemaVersion: browsercustody.SchemaVersion, CaptureConfig: receiver, Receipts: receipts, RunID: "run", ManifestSHA256: b01.ManifestSHA256, BridgeID: b01.BridgeID, BridgeConfigDigest: b01.BridgeConfigDigest,
		Mappings: []browsercustody.Mapping{{Scope: browserlink.Scope(list[0].Scope), ReceiptDigest: list[0].Digest, Role: "browser", HostID: "fixture-host", PID: 42, ProcessInstanceID: "11111111-1111-4111-8111-111111111111:42:100"}}}
	config := filepath.Join(filepath.Dir(receiver), "custody.json")
	if err := os.WriteFile(config, browserCLIJSON(t, cfg), 0600); err != nil {
		t.Fatal(err)
	}
	paths := store.ResolvePaths(root)
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, kind := range []string{"file_write", "network_connect"} {
		payload := fmt.Sprintf(`{"runtime_process_identity":"agentprov.runtime_process/v3","host_id":"fixture-host","process_instance_id":%q,"path":"/tmp/download","dst_ip":"127.0.0.1","dst_port":443}`, cfg.Mappings[0].ProcessInstanceID)
		if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,pid,payload,created_at) VALUES (?,'run','agentprov_ebpf',?,42,?,'2026-11-16T00:00:00Z')`, kind, kind, payload); err != nil {
			t.Fatal(err)
		}
	}
	page, err := (agentcontext.Service{DB: db}).Entries(context.Background(), agentcontext.PageOptions{RunID: "run"})
	if err != nil {
		t.Fatal(err)
	}
	var support agentcontext.Entry
	for _, e := range page.Entries {
		if e.Browser != nil && e.Browser.EventID == "end" {
			support = e
		}
	}
	if support.ID == "" {
		t.Fatal("missing custody witness")
	}
	return custodyFixture{root, config, receiver, receipts, cfg, db, support}
}

func runCustodyCLI(t *testing.T, root string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := NewRootCommand()
	var out, stderr bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	cmd.SetArgs(append([]string{"--data-dir", root}, args...))
	err := cmd.Execute()
	return out.Bytes(), err
}

func runtimeEdges(m provenance.GraphLensManifest) map[string]provenance.GraphLensEdge {
	out := map[string]provenance.GraphLensEdge{}
	for _, edge := range m.DerivedEdges {
		if edge.DerivationRule == browserlink.RuntimeRule {
			out[edge.ID] = edge
		}
	}
	return out
}

func custodyZIPEdges(t *testing.T, path string) map[string]provenance.GraphLensEdge {
	t.Helper()
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	shards := map[string]json.RawMessage{}
	for _, file := range z.File {
		if !strings.HasPrefix(file.Name, "data/") {
			continue
		}
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		var args []string
		call := strings.TrimSuffix(strings.TrimPrefix(string(raw), "window.AgentProvOffline.accept("), ");")
		if err := json.Unmarshal([]byte("["+call+"]"), &args); err != nil || len(args) != 2 {
			t.Fatalf("invalid replay wrapper: %v", err)
		}
		compressed, err := base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(gz)
		gz.Close()
		if err != nil {
			t.Fatal(err)
		}
		shards[args[0]] = body
	}
	read := func(ref staticdata.Ref, target any) {
		t.Helper()
		body, ok := shards[ref.Path]
		if !ok {
			t.Fatalf("missing replay shard %s", ref.Path)
		}
		if err := json.Unmarshal(body, target); err != nil {
			t.Fatalf("invalid replay shard %s: %v", ref.Path, err)
		}
	}
	out := map[string]provenance.GraphLensEdge{}
	lensIndexes := 0
	for _, body := range shards {
		var index struct {
			Graph staticdata.Ref            `json:"graph"`
			Views map[string]staticdata.Ref `json:"views"`
		}
		if json.Unmarshal(body, &index) != nil || len(index.Views) == 0 {
			continue
		}
		lensIndexes++
		var graph struct {
			SchemaVersion string                     `json:"schema_version"`
			Edges         []provenance.GraphLensEdge `json:"edges"`
		}
		if index.Graph.SHA256 != "" {
			read(index.Graph, &graph)
			if graph.SchemaVersion != "agentprovenance.replay_graph/v1" {
				t.Fatalf("unsupported graph encoding %q", graph.SchemaVersion)
			}
		}
		for _, ref := range index.Views {
			var view struct {
				provenance.ReplayLensView
				SchemaVersion string `json:"schema_version"`
				FocusIndexes  []int  `json:"focus_indexes"`
			}
			read(ref, &view)
			switch view.SchemaVersion {
			case "":
				if index.Graph.SHA256 != "" {
					t.Fatal("legacy view unexpectedly refers to a shared graph")
				}
			case "agentprovenance.replay_lens_view/v2":
				if index.Graph.SHA256 == "" {
					t.Fatal("shared view is missing its graph")
				}
				// Follow this lens's references; unrelated dictionary entries
				// must not satisfy the online/offline custody assertions.
				for _, i := range view.FocusIndexes {
					if i < 0 || i >= len(graph.Edges) {
						t.Fatalf("invalid focus edge index %d", i)
					}
					view.FocusEdges = append(view.FocusEdges, graph.Edges[i])
				}
			default:
				t.Fatalf("unsupported view encoding %q", view.SchemaVersion)
			}
			for _, edge := range view.FocusEdges {
				if edge.DerivationRule == browserlink.RuntimeRule {
					out[edge.ID] = edge
				}
			}
		}
	}
	if lensIndexes == 0 {
		t.Fatal("export contains no lens indexes")
	}
	return out
}

func TestBrowserCustodyGraphAndSelectedExportCLI(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_URL", "")
	for _, capture := range []string{"basic", "detailed"} {
		t.Run(capture, func(t *testing.T) {
			f := newCustodyFixture(t, capture)
			graphArgs := []string{"graph", "lens", "--run", "run", "--detail", "raw", "--json"}
			plain, err := runCustodyCLI(t, f.root, graphArgs...)
			if err != nil {
				t.Fatal(err)
			}
			var graph provenance.GraphLensManifest
			if err := json.Unmarshal(plain, &graph); err != nil || len(runtimeEdges(graph)) != 0 {
				t.Fatal("stored B01 JSON granted runtime authority")
			}
			authorized, err := runCustodyCLI(t, f.root, append(graphArgs, "--browser-custody-config", f.config)...)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(authorized, &graph); err != nil || len(runtimeEdges(graph)) != 4 {
				t.Fatalf("explicit CLI custody missing: %s %v", authorized, err)
			}
			for _, e := range runtimeEdges(graph) {
				if e.FromID == f.support.ObjectHash {
					t.Fatal("operation was promoted to OS cause")
				}
			}
			for _, mode := range []string{"complete", "source_excluded", "runtime_excluded", "no_config"} {
				path := filepath.Join(t.TempDir(), mode+".zip")
				args := []string{"dashboard", "export", "--run", "run", "--output", path}
				if mode != "no_config" {
					args = append(args, "--browser-custody-config", f.config)
				}
				if mode == "source_excluded" {
					args = append(args, "--exclude-record", "entry/"+f.support.ID)
				}
				if mode == "runtime_excluded" {
					args = append(args, "--exclude-category", "runtime")
				}
				if out, err := runCustodyCLI(t, f.root, args...); err != nil {
					t.Fatalf("%s export: %s %v", mode, out, err)
				}
				edges := custodyZIPEdges(t, path)
				if mode == "complete" {
					// JSON round trips change only interface value types, not content.
					a, b := browserCLIJSON(t, runtimeEdges(graph)), browserCLIJSON(t, edges)
					if !bytes.Equal(a, b) {
						t.Fatalf("online/offline custody projection differs: %s / %s", a, b)
					}
				} else if len(edges) != 0 {
					t.Fatalf("%s retained unsupported custody", mode)
				}
			}
		})
	}
}

func TestBrowserCustodyRejectsAuthorityAndRevalidatesSource(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_URL", "")
	for _, mode := range []string{"inside_capture", "inside_evidence", "wrong_pin", "wrong_bridge", "wrong_run", "wrong_scope", "unknown_receipt", "wrong_birth", "symlink", "public_file", "duplicate_key", "unknown_field", "tampered_journal", "tampered_receipt"} {
		t.Run(mode, func(t *testing.T) {
			f := newCustodyFixture(t, "basic")
			cfg := f.cfg
			path := f.config
			switch mode {
			case "inside_capture":
				path = filepath.Join(filepath.Dir(f.receipts), "self-grant.json")
			case "inside_evidence":
				dir := store.ResolvePaths(f.root).Artifacts
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(dir, "self-grant.json")
			case "wrong_pin":
				cfg.ManifestSHA256 = browserCLIHash([]byte("other"))
			case "wrong_bridge":
				cfg.BridgeID = "other"
			case "wrong_run":
				cfg.RunID = "other"
			case "wrong_scope":
				cfg.Mappings[0].Scope.Generation = "other"
			case "unknown_receipt":
				cfg.Mappings[0].ReceiptDigest = browserCLIHash([]byte("other"))
			case "wrong_birth":
				cfg.Mappings[0].ProcessInstanceID = "42"
			case "tampered_journal":
				journal := filepath.Join(filepath.Dir(f.receipts), "browser.jsonl")
				raw, _ := os.ReadFile(journal)
				raw = bytes.ReplaceAll(raw, []byte(`"operation":"click"`), []byte(`"operation":"other"`))
				if err := os.WriteFile(journal, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "tampered_receipt":
				if err := os.WriteFile(f.receipts, []byte(`[{}]`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			raw := browserCLIJSON(t, cfg)
			if mode == "duplicate_key" {
				raw = bytes.Replace(raw, []byte(`"run_id":"run"`), []byte(`"run_id":"other","run_id":"run"`), 1)
			}
			if mode == "unknown_field" {
				raw = append([]byte(`{"authentication":"verified",`), raw[1:]...)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "symlink" {
				link := filepath.Join(filepath.Dir(path), "linked.json")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			if mode == "public_file" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := browsercustody.Load(context.Background(), path, store.ResolvePaths(f.root)); err == nil {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
	f := newCustodyFixture(t, "basic")
	verified, err := browsercustody.Load(context.Background(), f.config, store.ResolvePaths(f.root))
	if err != nil {
		t.Fatal(err)
	}
	before, err := verified.Resolve(context.Background(), f.db, "run")
	if err != nil || len(before) != 1 {
		t.Fatalf("source validation: %+v %v", before, err)
	}
	if _, err := f.db.Exec(`DELETE FROM agent_context_entries WHERE run_id='run' AND id=?`, f.support.ID); err != nil {
		t.Fatal(err)
	}
	after, err := verified.Resolve(context.Background(), f.db, "run")
	if err != nil || len(after) != 0 {
		t.Fatalf("removed source granted stale custody: %v", err)
	}
	var decoded browsercustody.Verified
	if json.Unmarshal(browserCLIJSON(t, f.cfg), &decoded) == nil {
		t.Fatal("JSON manufactured opaque custody")
	}
}

func TestBrowserCustodyHTTPHasNoTrustFlag(t *testing.T) {
	f := newCustodyFixture(t, "basic")
	verified, err := browsercustody.Load(context.Background(), f.config, store.ResolvePaths(f.root))
	if err != nil {
		t.Fatal(err)
	}
	for _, trusted := range []bool{false, true} {
		s := dashboard.Server{DB: f.db}
		if trusted {
			s.BrowserCustody = verified
		}
		r := httptest.NewRequest("GET", "/api/lens?run=run&detail=raw&trusted=true&browser-custody-config="+f.config, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var graph provenance.GraphLensManifest
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &graph) != nil {
			t.Fatalf("graph API %d: %s", w.Code, w.Body.String())
		}
		if (len(runtimeEdges(graph)) == 4) != trusted {
			t.Fatal("HTTP request fields affected custody authority")
		}
	}
}

func TestBrowserCustodyExecutableGraphAndExport(t *testing.T) {
	if testing.Short() {
		t.Skip("executable CLI integration")
	}
	f := newCustodyFixture(t, "basic")
	binary := filepath.Join(t.TempDir(), "agentprov")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/agentprov")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual CLI: %s %v", out, err)
	}
	args := []string{"--data-dir", f.root, "graph", "lens", "--run", "run", "--detail", "raw", "--json", "--browser-custody-config", f.config}
	out, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("actual graph CLI: %s %v", out, err)
	}
	var graph provenance.GraphLensManifest
	if json.Unmarshal(out, &graph) != nil || len(runtimeEdges(graph)) != 4 {
		t.Fatalf("actual CLI lacks runtime layers: %s", out)
	}
	path := filepath.Join(t.TempDir(), "reader.zip")
	out, err = exec.Command(binary, "--data-dir", f.root, "dashboard", "export", "--run", "run", "--output", path, "--browser-custody-config", f.config).CombinedOutput()
	if err != nil {
		t.Fatalf("actual export CLI: %s %v", out, err)
	}
	if !reflect.DeepEqual(runtimeEdges(graph), custodyZIPEdges(t, path)) {
		t.Fatal("actual CLI online/export layers differ")
	}
}

func TestBrowserCustodyChineseHelpAndError(t *testing.T) {
	for _, args := range [][]string{{"--lang", "zh-CN", "graph", "lens", "--help"}, {"--lang", "zh-CN", "dashboard", "export", "--help"}} {
		out, err := runCustodyCLI(t, t.TempDir(), args...)
		if err != nil || !strings.Contains(string(out), "接收方自有的运行时映射配置") {
			t.Fatalf("custody help translation: %s %v", out, err)
		}
	}
	f := newCustodyFixture(t, "basic")
	f.cfg.Mappings[0].Scope.Generation = "other"
	if err := os.WriteFile(f.config, browserCLIJSON(t, f.cfg), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := browsercustody.Load(context.Background(), f.config, store.ResolvePaths(f.root))
	if err == nil || i18n.ErrorText(i18n.Chinese, err) != "浏览器进程归属回执或作用域不匹配" {
		t.Fatalf("custody error translation: %v", err)
	}
}

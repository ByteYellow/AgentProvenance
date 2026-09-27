package agentcontext

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func writeSource(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func codexHeader(id, parent, cwd string, at time.Time) string {
	payload := map[string]any{"id": id, "cwd": cwd}
	if parent != "" {
		payload["source"] = map[string]any{"subagent": map[string]any{"thread_spawn": map[string]any{"parent_thread_id": parent}}}
	}
	b, _ := json.Marshal(map[string]any{"type": "session_meta", "timestamp": at.Format(time.RFC3339Nano), "payload": payload})
	return string(b) + "\n"
}

func discoverTest(t *testing.T, opts DiscoverOptions) Inventory {
	t.Helper()
	inv, err := Discover(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestDiscoveryConcurrentSessionsNeverUsesNewestMtime(t *testing.T) {
	root, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "codex", Root: root, Workdir: cwd, Snapshot: true}
	before := discoverTest(t, opts)
	writeSource(t, filepath.Join(root, "custom", "rollout-a.jsonl"), codexHeader("a", "", cwd, now))
	writeSource(t, filepath.Join(root, "custom", "rollout-b.jsonl"), codexHeader("b", "", cwd, now.Add(time.Second)))
	selection := SelectOptions{Workdir: cwd, StartedAt: now.Add(-time.Second), EndedAt: now.Add(time.Minute)}
	after := discoverTest(t, opts)
	r := SelectSources(context.Background(), before, after, selection)
	if r.Status != Ambiguous || len(r.Sources) != 0 {
		t.Fatalf("concurrent sessions guessed: %+v", r)
	}
	selection.SessionID = "a"
	r = SelectSources(context.Background(), before, after, selection)
	if r.Status != OK || len(r.Sources) != 1 || r.Sources[0].SessionID != "a" || r.Sources[0].Binding != "explicit" {
		t.Fatalf("explicit identity: %+v", r)
	}
}

func TestDiscoveryIncludesOnlyRealChildIdentities(t *testing.T) {
	root, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "codex", Root: root, Workdir: cwd}
	before := discoverTest(t, opts)
	for _, item := range []struct{ id, parent, cwd string }{
		{"root", "", cwd}, {"real-child", "root", cwd}, {"nested", "real-child", cwd},
		{"unrelated", "", "/other"}, {"foreign-child", "unrelated", cwd},
	} {
		writeSource(t, filepath.Join(root, "rollout-"+item.id+".jsonl"), codexHeader(item.id, item.parent, item.cwd, now))
	}
	r := SelectSources(context.Background(), before, discoverTest(t, opts), SelectOptions{
		Workdir: cwd, StartedAt: now.Add(-time.Second), EndedAt: now.Add(time.Second)})
	if r.Status != OK || len(r.Sources) != 3 {
		t.Fatalf("children: %+v", r)
	}
	for _, s := range r.Sources {
		if s.SessionID == "unrelated" || s.SessionID == "foreign-child" {
			t.Fatal("cross-parent source selected")
		}
		if s.SessionID != "root" && (s.AgentID != s.SessionID || s.Binding != "matched") {
			t.Fatalf("child identity fabricated: %+v", s)
		}
	}
}

func TestDiscoveryRejectsDuplicateChildrenAndChangedLineage(t *testing.T) {
	root, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "codex", Root: root, Workdir: cwd}
	before := discoverTest(t, opts)
	writeSource(t, filepath.Join(root, "rollout-parent.jsonl"), codexHeader("parent", "", cwd, now))
	childPath := filepath.Join(root, "rollout-child.jsonl")
	writeSource(t, childPath, codexHeader("child", "parent", cwd, now))
	writeSource(t, filepath.Join(root, "copy", "rollout-child.jsonl"), codexHeader("child", "parent", cwd, now))
	r := SelectSources(context.Background(), before, discoverTest(t, opts), SelectOptions{
		SessionID: "parent", Workdir: cwd, StartedAt: now.Add(-time.Second), EndedAt: now.Add(time.Second)})
	if r.Status != Partial || len(r.Sources) != 1 || len(r.Issues) != 1 || r.Issues[0].Code != "duplicate_child_session_sources" {
		t.Fatalf("duplicate child guessed: %+v", r)
	}
	parsed, err := Parse(context.Background(), strings.NewReader(codexHeader("child", "other-parent", cwd, now)),
		ParseOptions{Harness: "codex", SessionID: "child", ParentSessionID: "parent", Binding: "exact"})
	if err != nil || parsed.Coverage.Status != Ambiguous || len(parsed.Records) != 0 {
		t.Fatalf("lineage changed after discovery: %+v %v", parsed.Coverage, err)
	}
}

func TestDiscoveryResumePreservesPrefixAndRejectsReplacement(t *testing.T) {
	root, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	path := filepath.Join(root, "rollout-resumed.jsonl")
	initial := codexHeader("resumed", "", cwd, now.Add(-time.Hour)) + `{"type":"response_item","payload":{"type":"function_call","call_id":"c","name":"exec_command","arguments":"{}"}}` + "\n"
	writeSource(t, path, initial)
	opts := DiscoverOptions{Harness: "codex", Root: root, Workdir: cwd, Snapshot: true}
	before := discoverTest(t, opts)
	resultLine := `{"type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"late result"}}` + "\n"
	writeSource(t, path, initial+resultLine)
	selection := SelectOptions{Workdir: cwd, SessionID: "resumed", StartedAt: now, EndedAt: now.Add(time.Minute)}
	r := SelectSources(context.Background(), before, discoverTest(t, opts), selection)
	if r.Status != OK || len(r.Sources) != 1 || r.Sources[0].AfterLine != 2 {
		t.Fatalf("resume: %+v", r)
	}
	s := testService(t)
	first, err := s.ImportFile(context.Background(), "run", r.Sources[0].ParseOptions("codex"))
	if err != nil || first.Stored != 1 || first.Coverage.FirstLine != 3 {
		t.Fatalf("resumed import: %+v %v", first, err)
	}
	page, _ := s.Entries(context.Background(), PageOptions{RunID: "run"})
	if page.Entries[0].Kind != "tool_result" || page.Entries[0].ToolName != "exec_command" {
		t.Fatal("prior call metadata lost or prior events reassigned")
	}
	repeat, err := s.ImportFile(context.Background(), "run", r.Sources[0].ParseOptions("codex"))
	if err != nil || repeat.Stored != 0 || repeat.Duplicates != 1 {
		t.Fatalf("repeat: %+v %v", repeat, err)
	}
	writeSource(t, path, strings.Replace(initial, "exec_command", "other_action", 1)+resultLine)
	replaced := SelectSources(context.Background(), before, discoverTest(t, opts), selection)
	if replaced.Status != Ambiguous || len(replaced.Sources) != 0 {
		t.Fatalf("changed prefix accepted: %+v", replaced)
	}
	// Also reject replacement between selection and import, with the same ID.
	bad, err := s.ImportFile(context.Background(), "run", r.Sources[0].ParseOptions("codex"))
	if err != nil || bad.Stored != 0 || bad.Coverage.Status != Ambiguous {
		t.Fatalf("import race: %+v %v", bad, err)
	}
}

func TestDiscoveryRejectsIncompleteInventoryAndWrongTime(t *testing.T) {
	root, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "codex", Root: root, Workdir: cwd}
	before := discoverTest(t, opts)
	path := filepath.Join(root, "rollout-old.jsonl")
	writeSource(t, path, codexHeader("old", "", cwd, now.Add(-time.Hour)))
	window := SelectOptions{Workdir: cwd, StartedAt: now, EndedAt: now.Add(time.Minute)}
	r := SelectSources(context.Background(), before, discoverTest(t, opts), window)
	if r.Status != Ambiguous || len(r.Sources) != 0 {
		t.Fatalf("mtime substituted for source time: %+v", r)
	}
	writeSource(t, path, codexHeader("new", "", cwd, now.Add(time.Second)))
	writeSource(t, filepath.Join(root, "rollout-broken.jsonl"), "{invalid}\n")
	after := discoverTest(t, opts)
	if after.Complete {
		t.Fatal("incomplete scan reported complete")
	}
	r = SelectSources(context.Background(), before, after, window)
	if r.Status != Ambiguous || len(r.Sources) != 0 {
		t.Fatalf("incomplete scan guessed unique: %+v", r)
	}
	window.Path = path
	r = SelectSources(context.Background(), before, after, window)
	if r.Status != Partial || len(r.Sources) != 1 {
		t.Fatalf("explicit path blocked by unrelated file: %+v", r)
	}
}

func TestDiscoveryZstdCursorIncludesEveryFrameAndDefersTail(t *testing.T) {
	root, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	path := filepath.Join(root, "custom", "session.v4.jsonl.zstd")
	header, _ := json.Marshal(map[string]any{"type": "session", "version": 4, "id": "dsh", "cwd": cwd, "createdAt": now.UnixMilli()})
	writer, _ := zstd.NewWriter(nil)
	defer writer.Close()
	frame := func(s string) []byte { return writer.EncodeAll([]byte(s), nil) }
	data := append(frame(string(header)+"\n"), frame(deepseekEvents)...)
	data = append(data, frame(`{"type":"assistant/message"`)...)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	inv := discoverTest(t, DiscoverOptions{Harness: "deepseek", Root: root, Workdir: cwd, Snapshot: true})
	if !inv.Complete || len(inv.Candidates) != 1 || inv.Candidates[0].Cursor.Lines != 9 || !inv.Candidates[0].Cursor.Valid {
		t.Fatalf("zstd cursor: %+v", inv)
	}
	budget := int64(10)
	_, code := snapshotCursor(context.Background(), path, &budget)
	if code != "source_cursor_limit" {
		t.Fatalf("budget ignored: %s", code)
	}
}

func TestDiscoveryCancellationAndMissingRoot(t *testing.T) {
	opts := DiscoverOptions{Harness: "codex", Root: filepath.Join(t.TempDir(), "not-created")}
	inv := discoverTest(t, opts)
	if !inv.Complete || len(inv.Candidates) != 0 {
		t.Fatalf("missing directory: %+v", inv)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, opts); err != context.Canceled {
		t.Fatalf("cancel lost: %v", err)
	}
}

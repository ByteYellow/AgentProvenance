//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/workspace"
)

type workspaceCLIFixture struct {
	config   string
	settings workspaceOperatorConfig
}

func newWorkspaceCLIFixture(t *testing.T, modify ...func(*workspaceOperatorConfig)) workspaceCLIFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := workspaceOperatorConfig{Schema: workspaceCLISchema, WorkspaceID: "cli-work", RunID: "run-workspace-cli", Root: filepath.Join(base, "work"), StateDir: filepath.Join(base, "state"), DataDir: filepath.Join(base, "data"), TargetFile: filepath.Join(base, "target.json"),
		Target: workspace.Target{ProducerID: "producer", InstanceID: "instance", Generation: "g1"}, AllowedOperations: []workspace.Operation{workspace.Read, workspace.Write, workspace.Edit, workspace.Execute}, BashTimeoutSeconds: 3}
	if err := os.Mkdir(c.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Root, "input.txt"), []byte("value=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, change := range modify {
		change(&c)
	}
	path := filepath.Join(base, "operator.json")
	workspaceWriteJSON(t, path, c)
	workspaceWriteJSON(t, c.TargetFile, c.Target)
	return workspaceCLIFixture{path, c}
}

func workspaceWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func workspaceCLIRequest(f workspaceCLIFixture, extra map[string]any) map[string]any {
	r := map[string]any{"workspace_id": f.settings.WorkspaceID, "target": f.settings.Target}
	for key, value := range extra {
		r[key] = value
	}
	return r
}

func callWorkspaceCLI(t *testing.T, f workspaceCLIFixture, op string, extra map[string]any) (workspaceToolResult, error) {
	t.Helper()
	raw, err := json.Marshal(workspaceCLIRequest(f, extra))
	if err != nil {
		t.Fatal(err)
	}
	root := NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetIn(bytes.NewReader(raw))
	root.SetArgs([]string{"workspace", op, "--config", f.config, "--json"})
	err = root.Execute()
	var result workspaceToolResult
	if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
		t.Fatalf("non-JSON CLI output: %q stderr=%q err=%v", stdout.String(), stderr.String(), err)
	}
	if result.Schema != workspaceResultSchema {
		t.Fatal(result)
	}
	return result, err
}

func workspaceCLIRequireOK(t *testing.T, f workspaceCLIFixture, op string, extra map[string]any) workspaceToolResult {
	t.Helper()
	r, err := callWorkspaceCLI(t, f, op, extra)
	if err != nil || !r.OK || r.ContextStatus != "stored" {
		t.Fatalf("%s failed: %+v %v", op, r, err)
	}
	return r
}

func TestWorkspaceCLIReadEditWriteBashActualRecord(t *testing.T) {
	f := newWorkspaceCLIFixture(t)
	i := workspaceCLIRequireOK(t, f, "inspect", nil)
	if i.View.Binding.Revision != 1 || len(i.Files) != 1 || i.OperationRef != "" {
		t.Fatal(i)
	}
	r := workspaceCLIRequireOK(t, f, "read", map[string]any{"path": "input.txt"})
	if *r.Content != "value=1\n" || r.ContentEvidence.Ref == "" || r.ContentEvidence.SourceSHA256 != r.SHA256 || r.OperationRef == "" {
		t.Fatal(r)
	}
	e := workspaceCLIRequireOK(t, f, "edit", map[string]any{"path": "input.txt", "old_text": "1", "new_text": "2", "count": 1, "expected_revision": r.View.Binding.Revision, "expected_digest": r.SHA256})
	if e.View.Binding.Revision != 2 {
		t.Fatal(e)
	}
	w := workspaceCLIRequireOK(t, f, "write", map[string]any{"path": "note.txt", "content": "untracked\n", "expected_digest": "absent"})
	if w.View.Binding.Revision != 3 {
		t.Fatal(w)
	}
	t.Setenv("W01_TEST_PROVIDER_SECRET", "synthetic-do-not-inherit")
	b := workspaceCLIRequireOK(t, f, "bash", map[string]any{"expected_revision": 3, "command": "test -z \"$W01_TEST_PROVIDER_SECRET\" && cat input.txt note.txt > result.txt && printf VERIFIED"})
	if b.Stdout != "VERIFIED" || b.View.LastReceipt.Record == nil || b.RecordToolCallID == "" || b.RecordToolCallID == b.ToolCallID || *b.View.LastReceipt.ExitCode != 0 || b.View.LastReceipt.InputRevision != 3 || b.View.Binding.Revision != 4 {
		t.Fatal(b)
	}
	data, err := os.ReadFile(filepath.Join(f.settings.Root, "result.txt"))
	if err != nil || string(data) != "value=2\nuntracked\n" {
		t.Fatalf("result: %s %v", data, err)
	}
	db, err := store.Open(store.ResolvePaths(f.settings.DataDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fork_attempts WHERE id=? AND tool_call_id=? AND workspace_path=?`, b.View.LastReceipt.Record.AttemptID, b.RecordToolCallID, f.settings.Root).Scan(&count); err != nil || count != 1 {
		t.Fatalf("record mismatch %d %v", count, err)
	}
	var snapshotPath string
	if err := db.QueryRow(`SELECT path FROM snapshots WHERE id=?`, b.View.LastReceipt.Record.BaseSnapshotID).Scan(&snapshotPath); err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(filepath.Join(snapshotPath, "input.txt"))
	if err != nil || string(baseline) != "value=2\n" {
		t.Fatalf("record input: %s %v", baseline, err)
	}
	page, err := (agentcontext.Service{DB: db, Paths: store.ResolvePaths(f.settings.DataDir)}).Entries(context.Background(), agentcontext.PageOptions{RunID: f.settings.RunID, ToolCallID: b.ToolCallID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("context entries: %+v", page)
	}
	for _, entry := range page.Entries {
		if entry.Source.Harness != "workspace-cli" || entry.ExecutionScope != agentcontext.CurrentExecution {
			t.Fatal(entry)
		}
		if entry.Kind == "tool_result" && !strings.Contains(strings.Join(entry.Source.BindingEvidence, " "), b.OperationRef) {
			t.Fatal("current CAS receipt not attached to trusted context")
		}
	}
}

func TestWorkspaceCLIConflictRereadAndInspectNeverExecutes(t *testing.T) {
	f := newWorkspaceCLIFixture(t)
	workspaceCLIRequireOK(t, f, "inspect", nil)
	workspaceCLIRequireOK(t, f, "write", map[string]any{"path": "input.txt", "content": "new", "expected_revision": 1})
	r, err := callWorkspaceCLI(t, f, "write", map[string]any{"path": "input.txt", "content": "stale", "expected_revision": 1})
	if err == nil || r.Error.Code != "conflict" || r.Error.NextAction != "reread" || r.OperationRef != "" || r.View.Binding.Revision != 2 {
		t.Fatalf("conflict response: %+v %v", r, err)
	}
	for range 3 {
		r = workspaceCLIRequireOK(t, f, "inspect", nil)
		if r.View.Binding.Revision != 2 {
			t.Fatal(r)
		}
	}
	for _, extra := range []map[string]any{{"command": "touch should-not-run"}, {"content": "not a query"}, {"evidence_ref": "sha256:other-run"}, {"tool_call_id": "model-selected"}, {"run_id": "other-run"}} {
		r, err := callWorkspaceCLI(t, f, "inspect", extra)
		if err == nil || r.Error.Code != "invalid_request" {
			t.Fatalf("unsafe inspect: %+v %v", r, err)
		}
	}
	db, err := store.Open(store.ResolvePaths(f.settings.DataDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fork_attempts`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("inspect executed: %d %v", count, err)
	}
	data, err := os.ReadFile(filepath.Join(f.settings.Root, "input.txt"))
	if err != nil || string(data) != "new" {
		t.Fatal("conflict overwrote current bytes")
	}
}

func TestWorkspaceCLIConfiguredTargetReloadAndNoImplicitRebind(t *testing.T) {
	f := newWorkspaceCLIFixture(t)
	workspaceCLIRequireOK(t, f, "inspect", nil)
	updated := f.settings.Target
	updated.Generation = "g2"
	workspaceWriteJSON(t, f.settings.TargetFile, updated)
	for _, op := range []string{"inspect", "read", "bash"} {
		extra := map[string]any{}
		if op == "read" {
			extra["path"] = "input.txt"
		}
		if op == "bash" {
			extra["command"] = "touch never"
			extra["expected_revision"] = 1
		}
		r, err := callWorkspaceCLI(t, f, op, extra)
		if err == nil || r.Error.Code != "stale_target" || r.Error.NextAction != "operator_rebind" {
			t.Fatalf("stale %s: %+v %v", op, r, err)
		}
	}
	if _, err := os.Stat(filepath.Join(f.settings.Root, "never")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestWorkspaceCLITargetChangesDuringBash(t *testing.T) {
	f := newWorkspaceCLIFixture(t)
	workspaceCLIRequireOK(t, f, "inspect", nil)
	done := make(chan workspaceToolResult, 1)
	go func() {
		r, _ := callWorkspaceCLI(t, f, "bash", map[string]any{"command": "printf running > marker; sleep 0.4; printf done", "expected_revision": 1})
		done <- r
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(f.settings.Root, "marker")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Bash did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	target := f.settings.Target
	target.Generation = "restored"
	workspaceWriteJSON(t, f.settings.TargetFile, target)
	r := <-done
	if r.OK || r.Error.Code != "stale_target" {
		t.Fatal(r)
	}
}

func TestWorkspaceCLIConcurrentCASAcrossCommands(t *testing.T) {
	f := newWorkspaceCLIFixture(t)
	workspaceCLIRequireOK(t, f, "inspect", nil)
	results := make(chan workspaceToolResult, 4)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := callWorkspaceCLI(t, f, "write", map[string]any{"path": "input.txt", "content": "winner", "expected_revision": 1})
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for r := range results {
		if r.OK {
			success++
		} else if r.Error.Code == "conflict" {
			conflict++
		} else {
			t.Fatal(r)
		}
	}
	if success != 1 || conflict != 3 {
		t.Fatalf("winners=%d conflicts=%d", success, conflict)
	}
}

func TestWorkspaceCLIConfigOwnershipPathsAndAllowedOperations(t *testing.T) {
	for _, change := range []func(*workspaceOperatorConfig){
		func(c *workspaceOperatorConfig) { c.Schema = "unknown" }, func(c *workspaceOperatorConfig) { c.StateDir = filepath.Join(c.Root, "state") },
		func(c *workspaceOperatorConfig) { c.DataDir = filepath.Join(c.Root, "data") }, func(c *workspaceOperatorConfig) { c.Target.Generation = "" },
		func(c *workspaceOperatorConfig) { c.BashTimeoutSeconds = 301 }, func(c *workspaceOperatorConfig) { c.AllowedOperations = []workspace.Operation{workspace.Delete} },
	} {
		f := newWorkspaceCLIFixture(t, change)
		if r, err := callWorkspaceCLI(t, f, "inspect", nil); err == nil || r.OK {
			t.Fatal("invalid config accepted")
		}
	}
	f := newWorkspaceCLIFixture(t)
	if err := os.Chmod(f.config, 0o666); err != nil {
		t.Fatal(err)
	}
	if r, err := callWorkspaceCLI(t, f, "inspect", nil); err == nil || r.Error.Code != "unsafe_path" {
		t.Fatal(r, err)
	}
	if err := os.Chmod(f.config, 0o600); err != nil {
		t.Fatal(err)
	}
	link := f.config + "-link"
	if err := os.Symlink(f.config, link); err != nil {
		t.Fatal(err)
	}
	f.config = link
	if r, err := callWorkspaceCLI(t, f, "inspect", nil); err == nil || r.Error.Code != "unsafe_path" {
		t.Fatal(r, err)
	}
	ro := newWorkspaceCLIFixture(t, func(c *workspaceOperatorConfig) { c.AllowedOperations = []workspace.Operation{workspace.Read} })
	if r, err := callWorkspaceCLI(t, ro, "bash", map[string]any{"expected_revision": 1, "command": "touch no"}); err == nil || r.Error.Code != "forbidden" {
		t.Fatal(r, err)
	}
}

func TestWorkspaceCLIBashBoundedOutputAndExitStatus(t *testing.T) {
	f := newWorkspaceCLIFixture(t, func(c *workspaceOperatorConfig) { c.Limits.OutputBytes = 32 })
	workspaceCLIRequireOK(t, f, "inspect", nil)
	r, err := callWorkspaceCLI(t, f, "bash", map[string]any{"expected_revision": 1, "command": "printf '%1000s' x"})
	if err == nil || r.Error.Code != "limit_exceeded" || !r.OutputTruncated || r.Stdout != "" || r.View.LastReceipt.Stdout.State != "limit_omitted" {
		t.Fatalf("output limit: %+v %v", r, err)
	}
	r = workspaceCLIRequireOK(t, f, "bash", map[string]any{"expected_revision": 2, "command": "exit 7"})
	if *r.View.LastReceipt.ExitCode != 7 {
		t.Fatal(r)
	}
}

func TestWorkspaceCLIRefsCannotCrossRun(t *testing.T) {
	f := newWorkspaceCLIFixture(t)
	r := workspaceCLIRequireOK(t, f, "read", map[string]any{"path": "input.txt"})
	paths := store.ResolvePaths(f.settings.DataDir)
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	foreign, err := (provenance.ObjectStore{DB: db, Paths: paths}).PutTextContent(provenance.TextContentInput{RunID: "other-run", SourceID: "foreign", Text: "not this tool's input"})
	if err != nil {
		t.Fatal(err)
	}
	v := workspace.View{Binding: r.View.Binding, LastReceipt: r.View.LastReceipt, Snapshot: workspace.Snapshot{Entries: []workspace.Entry{{Content: workspace.Content{State: "stored", Ref: foreign.Ref}}}}}
	if err := verifyWorkspaceRefs(context.Background(), db, f.settings, v); !errors.Is(err, workspace.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE provenance_objects SET run_id='other-run' WHERE hash=?`, r.View.Binding.EvidenceRef); err != nil {
		t.Fatal(err)
	}
	bad, err := callWorkspaceCLI(t, f, "read", map[string]any{"path": "input.txt"})
	if err == nil || bad.Error.Code != "recovery_required" || bad.Content != nil || bad.OperationRef != "" || bad.ContentEvidence != nil {
		t.Fatalf("foreign ref escaped: %+v %v", bad, err)
	}
}

func TestWorkspaceCLIStrictJSONAndCurrentDirectoryIndependence(t *testing.T) {
	f := newWorkspaceCLIFixture(t)
	for _, raw := range []string{"null", "{}", "{} {}", `{"workspace_id":"cli-work","target":{}}`, "{bad"} {
		r, err := runWorkspaceTool(context.Background(), strings.NewReader(raw), f.config, "inspect")
		if err == nil || r.OK {
			t.Fatal(raw, r, err)
		}
	}
	workspaceCLIRequireOK(t, f, "inspect", nil)
	for _, path := range []string{"../escape", "/tmp/escape", ".git/config"} {
		if r, err := callWorkspaceCLI(t, f, "write", map[string]any{"path": path, "content": "bad", "expected_revision": 1}); err == nil || r.Error.Code != "unsafe_path" {
			t.Fatal(r, err)
		}
	}
}

func TestWorkspaceCLIProcess(t *testing.T) {
	if os.Getenv("AGENTPROV_WORKSPACE_CLI_HELPER") != "1" {
		return
	}
	root := NewRootCommand()
	root.SetArgs([]string{"workspace", "bash", "--config", os.Getenv("AGENTPROV_WORKSPACE_CLI_CONFIG"), "--json"})
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestWorkspaceCLISignalCancelsActualRecordAndPersistsOutcome(t *testing.T) {
	f := newWorkspaceCLIFixture(t, func(c *workspaceOperatorConfig) { c.BashTimeoutSeconds = 30 })
	workspaceCLIRequireOK(t, f, "inspect", nil)
	raw, err := json.Marshal(workspaceCLIRequest(f, map[string]any{"expected_revision": 1, "command": "printf started > marker; sleep 30; printf survived > must-not-exist"}))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkspaceCLIProcess$")
	cmd.Env = append(os.Environ(), "AGENTPROV_WORKSPACE_CLI_HELPER=1", "AGENTPROV_WORKSPACE_CLI_CONFIG="+f.config)
	cmd.Stdin = bytes.NewReader(raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			<-done
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(f.settings.Root, "marker")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("record child did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		waited = true
	case <-time.After(10 * time.Second):
		t.Fatal("CLI signal did not cancel record")
	}
	var result workspaceToolResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("missing final JSON: %s %s %v", stdout.String(), stderr.String(), err)
	}
	if result.OK || result.Error.Code != "interrupted" || result.View == nil || result.View.LastReceipt.Record == nil || *result.View.LastReceipt.ExitCode != 130 || result.ContextStatus != "stored" {
		t.Fatalf("cancelled outcome: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(f.settings.Root, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled Bash continued")
	}
	view := workspaceCLIRequireOK(t, f, "inspect", nil)
	if view.View.Binding.Revision != 2 || view.View.LastReceipt.Record.AttemptID != result.View.LastReceipt.Record.AttemptID {
		t.Fatal("inspect lost or replayed cancelled execution")
	}
}

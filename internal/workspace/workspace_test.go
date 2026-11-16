//go:build linux || darwin

package workspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
	"golang.org/x/sys/unix"
)

type fixture struct {
	w    *Workspace
	c    Config
	root string
}

var testTarget = Target{ProducerID: "producer", InstanceID: "instance", Generation: "generation-1"}

func newFixture(t *testing.T, files map[string]string, options ...func(*Config)) fixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "work")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for p, data := range files {
		path := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := store.Init(filepath.Join(base, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := Config{StateDir: filepath.Join(base, "binding"), RunID: "run-workspace", Objects: provenance.ObjectStore{DB: db, Paths: paths},
		Binding:       WorkspaceBinding{WorkspaceID: "workspace-1", Target: testTarget, Root: root, AllowedOperations: []Operation{Read, Write, Edit, Rename, Delete, Chmod, Execute}},
		CurrentTarget: func(context.Context) (Target, error) { return testTarget, nil }}
	for _, option := range options {
		option(&c)
	}
	w, err := Open(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{w: w, c: c, root: root}
}

func request(path string, revision uint64) Request {
	return Request{WorkspaceID: "workspace-1", Target: testTarget, Path: path, ExpectedRevision: &revision, ToolCallID: "tool-1"}
}

func inspect(t *testing.T, w *Workspace) View {
	t.Helper()
	v, err := w.Inspect(context.Background(), Request{WorkspaceID: "workspace-1", Target: testTarget})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func checkFile(t *testing.T, root, path, want string, mode fs.FileMode) {
	t.Helper()
	p := filepath.Join(root, path)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != want || info.Mode().Perm() != mode {
		t.Fatalf("file %s = %q %v, want %q %v", path, raw, info.Mode().Perm(), want, mode)
	}
}

func checkEvidence(t *testing.T, f fixture, v View) {
	t.Helper()
	if v.Binding.ManifestDigest != v.Snapshot.Digest || v.Snapshot.Digest != snapshotDigest(v.Snapshot.Entries) || v.Binding.ManifestRef == "" || v.Binding.EvidenceRef != v.LastReceipt.Ref {
		t.Fatalf("invalid view: %+v", v)
	}
	for _, e := range v.Snapshot.Entries {
		if e.Content.State == "stored" {
			if err := provenance.VerifyTextContent(f.c.Objects.DB, f.c.RunID, e.Content.Ref); err != nil {
				t.Fatal(err)
			}
		}
	}
	s := journal{RunID: f.c.RunID, View: v}
	if err := validateHead(context.Background(), f.c.Objects, s); err != nil {
		t.Fatal(err)
	}
}

func TestReadEditRecordSameAuthoritativeBytes(t *testing.T) {
	f := newFixture(t, map[string]string{"main.txt": "uncommitted input\n", "untracked.txt": "not in git\n"})
	ctx := context.Background()
	r, err := f.w.ReadFile(ctx, request("main.txt", 1))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Data) != "uncommitted input\n" || r.SHA256 != digestBytes(r.Data) {
		t.Fatal("read did not use actual remote bytes")
	}
	e := EditRequest{Request: request("main.txt", 1), Old: []byte("input"), New: []byte("edited"), Count: 1}
	e.ExpectedDigest = r.SHA256
	v, err := f.w.EditFile(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if v.Binding.Revision != 2 {
		t.Fatal(v.Binding.Revision)
	}
	var executedInput ExecutionInput
	v, err = f.w.ObserveExecution(ctx, request("", 2), func(ctx context.Context, input ExecutionInput) (ExecutionResult, error) {
		executedInput = input
		if input.Binding.Mode != RemoteAuthoritative || input.Binding.Root != f.root {
			t.Fatal("wrong runner binding")
		}
		rr, err := (record.Service{DB: f.c.Objects.DB, Paths: f.c.Objects.Paths, Options: record.Options{AllowShell: true, AllowAnyWorkdir: true}}).RunContext(ctx, record.Request{
			RunID: f.c.RunID, Name: "workspace-conformance", Workdir: input.Binding.Root,
			Command: []string{"sh", "-c", "cat main.txt untracked.txt > result.txt; chmod 755 result.txt"}, SampleIntervalMS: 10, PostRootGraceMS: 10,
		})
		if err != nil {
			return ExecutionResult{}, err
		}
		var snapshotPath string
		if err := f.c.Objects.DB.QueryRow(`SELECT path FROM snapshots WHERE id=?`, rr.BaseSnapshotID).Scan(&snapshotPath); err != nil {
			t.Fatal(err)
		}
		checkFile(t, snapshotPath, "main.txt", "uncommitted edited\n", 0o644)
		return ExecutionResult{ExitCode: rr.ExitCode, Record: &RecordReference{RunID: rr.RunID, RolloutID: rr.RolloutID, AttemptID: rr.AttemptID, BaseSnapshotID: rr.BaseSnapshotID}, Stdout: []byte("complete\n")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.LastReceipt.InputRevision != 2 || v.LastReceipt.OutputRevision != 3 || v.LastReceipt.InputManifest != executedInput.Binding.ManifestDigest || v.LastReceipt.Record == nil || v.LastReceipt.Claim != "filesystem_observation" {
		t.Fatalf("execution receipt: %+v", v.LastReceipt)
	}
	checkFile(t, f.root, "result.txt", "uncommitted edited\nnot in git\n", 0o755)
	checkEvidence(t, f, v)
	page, err := provenance.ReadTextContentPage(f.c.Objects.DB, f.c.RunID, v.LastReceipt.Stdout.Ref, 0, 100)
	if err != nil || page.Content != "complete\n" {
		t.Fatalf("stdout evidence: %+v %v", page, err)
	}
}

func TestModeRenameDeleteAndOldManifestCounterexample(t *testing.T) {
	f := newFixture(t, map[string]string{"script": "echo example\n", "dir/keep": "keep"})
	ctx := context.Background()
	before := inspect(t, f.w)
	oldBefore, err := state.BuildManifest(f.root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.w.ChmodFile(ctx, ChmodRequest{Request: request("script", 1), Mode: 0o755})
	if err != nil {
		t.Fatal(err)
	}
	oldAfter, err := state.BuildManifest(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if oldBefore.Hash != oldAfter.Hash {
		t.Fatal("counterexample changed: old manifest now includes mode")
	}
	if before.Binding.ManifestDigest == v.Binding.ManifestDigest || v.LastReceipt.Changes[0].Kind != "mode_changed" {
		t.Fatal("workspace digest lost chmod")
	}
	v, err = f.w.WriteFile(ctx, WriteRequest{Request: request("script", 2), Data: []byte("echo changed\n")})
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, f.root, "script", "echo changed\n", 0o755)
	v, err = f.w.RenameFile(ctx, RenameRequest{Request: request("script", 3), Destination: "dir/moved"})
	if err != nil {
		t.Fatal(err)
	}
	if v.LastReceipt.Destination != "dir/moved" || len(v.LastReceipt.Changes) != 2 {
		t.Fatalf("rename receipt: %+v", v.LastReceipt)
	}
	checkFile(t, f.root, "dir/moved", "echo changed\n", 0o755)
	v, err = f.w.DeleteFile(ctx, request("dir/moved", 4))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "dir/moved")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if v.Binding.Revision != 5 || v.LastReceipt.Changes[0].Kind != "deleted" || v.LastReceipt.Changes[0].Before.Mode != "-rwxr-xr-x" {
		t.Fatal(v.LastReceipt)
	}
	entries, err := state.BuildFileManifest(f.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		got := findEntry(v.Snapshot, e.Path)
		if got == nil || got.FileEntry != e {
			t.Fatalf("state manifest compatibility: %+v %+v", e, got)
		}
	}
	checkEvidence(t, f, v)
}

func TestRevisionDigestAndCreateConflictsNeverOverwrite(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "original", "dest": "destination"})
	ctx := context.Background()
	bad := []Request{request("file", 0), request("file", 2), {WorkspaceID: "workspace-1", Target: testTarget, Path: "file", ExpectedDigest: Absent}, {WorkspaceID: "workspace-1", Target: testTarget, Path: "file", ExpectedDigest: strings.Repeat("0", 64)}}
	for _, r := range bad {
		if _, err := f.w.WriteFile(ctx, WriteRequest{Request: r, Data: []byte("lost update")}); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if _, err := f.w.RenameFile(ctx, RenameRequest{Request: request("file", 1), Destination: "dest"}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	missing := request("file", 1)
	missing.ExpectedRevision = nil
	if _, err := f.w.DeleteFile(ctx, missing); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := f.w.EditFile(ctx, EditRequest{Request: request("file", 1), Old: []byte("original"), New: []byte("bad"), Count: 2}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	checkFile(t, f.root, "file", "original", 0o644)
	checkFile(t, f.root, "dest", "destination", 0o644)
	if inspect(t, f.w).Binding.Revision != 1 {
		t.Fatal("conflict advanced revision")
	}
	r := request("new", 1)
	r.ExpectedRevision = nil
	r.ExpectedDigest = Absent
	v, err := f.w.WriteFile(ctx, WriteRequest{Request: r, Data: []byte("created")})
	if err != nil {
		t.Fatal(err)
	}
	r = request("file", 2)
	r.ExpectedRevision = nil
	r.ExpectedDigest = digestBytes([]byte("original"))
	v, err = f.w.WriteFile(ctx, WriteRequest{Request: r, Data: []byte("digest only")})
	if err != nil {
		t.Fatal(err)
	}
	if v.Binding.Revision != 3 {
		t.Fatal(v.Binding.Revision)
	}
}

func TestExternalMutationsAreObservationsAndStaleWritesConflict(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "original", "deleted": "remove"})
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(f.root, "file"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.root, "deleted")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.root, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	v, err := f.w.WriteFile(ctx, WriteRequest{Request: request("file", 1), Data: []byte("overwrite")})
	if !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if v.Binding.Revision != 2 || v.LastReceipt.Kind != "external_observation" || v.LastReceipt.Claim != "filesystem_observation" || len(v.LastReceipt.Changes) != 3 {
		t.Fatalf("external observation: %+v", v)
	}
	checkFile(t, f.root, "file", "outside", 0o644)
	v, err = f.w.ObserveExecution(ctx, request("", 2), func(ctx context.Context, i ExecutionInput) (ExecutionResult, error) {
		return ExecutionResult{}, os.WriteFile(filepath.Join(i.Binding.Root, "file"), []byte("during run"), 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.LastReceipt.Claim != "filesystem_observation" || v.LastReceipt.InputRevision != 2 || v.LastReceipt.OutputRevision != 3 {
		t.Fatal(v.LastReceipt)
	}
	checkEvidence(t, f, v)
}

func TestTargetGenerationAndBindingCannotBeSilentlyRebound(t *testing.T) {
	current := testTarget
	f := newFixture(t, map[string]string{"file": "original"}, func(c *Config) { c.CurrentTarget = func(context.Context) (Target, error) { return current, nil } })
	ctx := context.Background()
	for _, target := range []Target{{}, {ProducerID: "other", InstanceID: testTarget.InstanceID, Generation: testTarget.Generation}, {ProducerID: testTarget.ProducerID, InstanceID: "other", Generation: testTarget.Generation}, {ProducerID: testTarget.ProducerID, InstanceID: testTarget.InstanceID, Generation: "old"}} {
		r := request("file", 1)
		r.Target = target
		if _, err := f.w.WriteFile(ctx, WriteRequest{Request: r, Data: []byte("wrong")}); !errors.Is(err, ErrStaleTarget) {
			t.Fatal(err)
		}
	}
	current.Generation = "generation-2"
	if _, err := f.w.ReadFile(ctx, request("file", 1)); !errors.Is(err, ErrStaleTarget) {
		t.Fatal(err)
	}
	c := f.c
	c.Binding.Target = current
	if _, err := Open(ctx, c); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	checkFile(t, f.root, "file", "original", 0o644)
	current = testTarget
	for _, change := range []func(*Config){func(c *Config) { c.Binding.WorkspaceID = "different" }, func(c *Config) { c.Binding.AllowedOperations = []Operation{Read} }, func(c *Config) { c.Limits.FileBytes = 1024 }, func(c *Config) { c.RunID = "different" }} {
		c := f.c
		change(&c)
		if _, err := Open(ctx, c); !errors.Is(err, ErrConflict) {
			t.Fatalf("binding changed: %v", err)
		}
	}
}

func TestPermissionsAndPathSafety(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "original", "Dir/nested": "nested"})
	ctx := context.Background()
	for _, path := range []string{"", ".", "..", "../outside", "/outside", "Dir/../file", "Dir//nested", "Dir/./nested", "Dir\\nested", ".git/config", ".agentprov/db", "dir/nested", "FILE", "x\x00y"} {
		_, err := f.w.WriteFile(ctx, WriteRequest{Request: request(path, 1), Data: []byte("unsafe")})
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%q: %v", path, err)
		}
	}
	for _, kind := range []string{"symlink", "directory_symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			outside := filepath.Join(filepath.Dir(f.root), "outside")
			if err := os.WriteFile(outside, []byte("outside stays"), 0o644); err != nil {
				t.Fatal(err)
			}
			bad := filepath.Join(f.root, "bad")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(outside, bad)
			case "directory_symlink":
				err = os.Symlink(filepath.Dir(f.root), bad)
			case "hardlink":
				err = os.Link(outside, bad)
			case "fifo":
				err = unix.Mkfifo(bad, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(bad)
			_, err = f.w.ReadFile(ctx, request("bad", 1))
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatal(err)
			}
			checkFile(t, filepath.Dir(f.root), "outside", "outside stays", 0o644)
		})
	}
	for _, mode := range []fs.FileMode{fs.ModeSetuid | 0o755, fs.ModeSticky | 0o755, 0o4755} {
		if _, err := f.w.ChmodFile(ctx, ChmodRequest{Request: request("file", 1), Mode: mode}); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	ro := newFixture(t, map[string]string{"file": "readable"}, func(c *Config) { c.Binding.AllowedOperations = []Operation{Read} })
	if _, err := ro.w.DeleteFile(ctx, request("file", 1)); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := ro.w.ObserveExecution(ctx, request("", 1), func(context.Context, ExecutionInput) (ExecutionResult, error) {
		t.Fatal("forbidden runner called")
		return ExecutionResult{}, nil
	}); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
}

func TestBoundsBinaryAndRedactedEvidence(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "abc"}, func(c *Config) { c.Limits = Limits{FileBytes: 16, TotalBytes: 32, Entries: 4, OutputBytes: 8} })
	ctx := context.Background()
	if _, err := f.w.WriteFile(ctx, WriteRequest{Request: request("file", 1), Data: bytes.Repeat([]byte("x"), 17)}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	v, err := f.w.WriteFile(ctx, WriteRequest{Request: request("binary", 1), Data: []byte{0, 0xff, 1}})
	if err != nil {
		t.Fatal(err)
	}
	if e := findEntry(v.Snapshot, "binary"); e.Content.State != "binary_omitted" || e.Hash != digestBytes([]byte{0, 0xff, 1}) {
		t.Fatal(e)
	}
	v, err = f.w.ObserveExecution(ctx, request("", 2), func(context.Context, ExecutionInput) (ExecutionResult, error) {
		return ExecutionResult{Stdout: bytes.Repeat([]byte("x"), 9)}, nil
	})
	if !errors.Is(err, ErrLimit) || v.LastReceipt.Stdout.State != "limit_omitted" || v.Binding.Revision != 3 {
		t.Fatalf("output bounds: %+v %v", v, err)
	}
	if err := os.WriteFile(filepath.Join(f.root, "large"), bytes.Repeat([]byte("x"), 17), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.Inspect(ctx, request("", 3)); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	// Synthetic credential fixture exercises the existing redactor, not a real key.
	secret := "sk-proj-" + strings.Repeat("example", 12)
	g := newFixture(t, map[string]string{"config.txt": "key=" + secret + "\n"})
	u := inspect(t, g.w)
	e := findEntry(u.Snapshot, "config.txt")
	if !e.Content.Redacted || e.Content.StoredSHA256 == e.Hash {
		t.Fatalf("redaction identity lost: %+v", e)
	}
	raw, err := os.ReadFile(filepath.Join(g.c.StateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("raw secret entered journal")
	}
	checkEvidence(t, g, u)
}

func TestConcurrentCheckApplyRevisionAcrossHandles(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	ctx := context.Background()
	other, err := Open(ctx, f.c)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			w := f.w
			if i%2 == 1 {
				w = other
			}
			_, err := w.WriteFile(ctx, WriteRequest{Request: request("file", 1), Data: []byte(fmt.Sprintf("winner-%d", i))})
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	ok, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || conflicts != 15 || inspect(t, f.w).Binding.Revision != 2 {
		t.Fatalf("success=%d conflicts=%d", ok, conflicts)
	}
}

func TestExecutionLeaseAndCancellation(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	ctx := context.Background()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := f.w.ObserveExecution(ctx, request("", 1), func(ctx context.Context, i ExecutionInput) (ExecutionResult, error) {
			close(started)
			<-release
			return ExecutionResult{}, nil
		})
		done <- err
	}()
	<-started
	short, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	_, err := f.w.WriteFile(short, WriteRequest{Request: request("file", 1), Data: []byte("not allowed while running")})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	checkFile(t, f.root, "file", "base", 0o644)
	cancelled, cancel := context.WithCancel(ctx)
	v, err := f.w.ObserveExecution(cancelled, request("", 2), func(context.Context, ExecutionInput) (ExecutionResult, error) {
		cancel()
		return ExecutionResult{}, context.Canceled
	})
	if !errors.Is(err, context.Canceled) || v.LastReceipt.Outcome != "runner_error" || v.Binding.Revision != 3 {
		t.Fatalf("cancel completion: %+v %v", v, err)
	}
}

func TestEvidenceFailureBeforeAndAfterMutation(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	ctx := context.Background()
	if _, err := f.c.Objects.DB.Exec(`CREATE TRIGGER reject_workspace BEFORE INSERT ON provenance_objects WHEN NEW.object_type='workspace_operation' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.ReadFile(ctx, request("file", 1)); err == nil {
		t.Fatal("read returned evidence-free data")
	}
	if _, err := f.w.WriteFile(ctx, WriteRequest{Request: request("file", 1), Data: []byte("applied")}); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	checkFile(t, f.root, "file", "applied", 0o644)
	dir, err := openDir(f.c.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := loadJournal(dir)
	dir.Close()
	if err != nil {
		t.Fatal(err)
	}
	if s.View.Binding.Revision != 1 || s.Pending == nil {
		t.Fatal("failed evidence published revision")
	}
	if _, err := f.c.Objects.DB.Exec(`DROP TRIGGER reject_workspace`); err != nil {
		t.Fatal(err)
	}
	v := inspect(t, f.w)
	if v.Binding.Revision != 2 || v.LastReceipt.Outcome != "outcome_unknown" || v.LastReceipt.Kind != "recovery_observation" {
		t.Fatal(v)
	}
	checkEvidence(t, f, v)
}

func TestCrashRecoveryAtDurableBoundaries(t *testing.T) {
	for _, stage := range []string{"after_intent", "after_apply", "after_evidence", "after_head"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t, map[string]string{"file": "base"})
			cmd := helperCommand(t, f, stage, "changed")
			raw, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("child did not crash: %v %s", err, raw)
			}
			w, err := Open(context.Background(), f.c)
			if err != nil {
				t.Fatal(err)
			}
			v := inspect(t, w)
			want := "changed"
			if stage == "after_intent" {
				want = "base"
			}
			checkFile(t, f.root, "file", want, 0o644)
			if v.Binding.Revision != 2 {
				t.Fatal(v.Binding.Revision)
			}
			if stage == "after_head" {
				if v.LastReceipt.Outcome != "applied" {
					t.Fatal(v.LastReceipt)
				}
			} else if v.LastReceipt.Outcome != "outcome_unknown" || v.LastReceipt.Claim != "filesystem_observation" {
				t.Fatal(v.LastReceipt)
			}
			if _, err := w.WriteFile(context.Background(), WriteRequest{Request: request("file", 1), Data: []byte("replay")}); !errors.Is(err, ErrConflict) {
				t.Fatal(err)
			}
			checkEvidence(t, f, v)
		})
	}
}

func helperCommand(t *testing.T, f fixture, stage, data string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkspaceSubprocess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "W01_HELPER=1", "W01_ROOT="+f.root, "W01_STATE="+f.c.StateDir, "W01_STORE="+f.c.Objects.Paths.Root, "W01_STAGE="+stage, "W01_DATA="+data)
	return cmd
}

func TestWorkspaceSubprocess(t *testing.T) {
	if os.Getenv("W01_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	paths := store.ResolvePaths(os.Getenv("W01_STORE"))
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w, err := Open(context.Background(), Config{StateDir: os.Getenv("W01_STATE"), RunID: "run-workspace", Objects: provenance.ObjectStore{DB: db, Paths: paths},
		Binding: WorkspaceBinding{WorkspaceID: "workspace-1", Target: testTarget, Root: os.Getenv("W01_ROOT"), AllowedOperations: []Operation{Read, Write, Edit, Rename, Delete, Chmod, Execute}}, CurrentTarget: func(context.Context) (Target, error) { return testTarget, nil }})
	if err != nil {
		t.Fatal(err)
	}
	w.fault = func(stage string) error {
		if stage == os.Getenv("W01_STAGE") {
			os.Exit(23)
		}
		return nil
	}
	if os.Getenv("W01_STAGE") == "execute_during" {
		_, err = w.ObserveExecution(context.Background(), request("", 1), func(_ context.Context, input ExecutionInput) (ExecutionResult, error) {
			if err := os.WriteFile(filepath.Join(input.Binding.Root, "ran-once"), []byte("once"), 0o644); err != nil {
				t.Fatal(err)
			}
			os.Exit(23)
			return ExecutionResult{}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	_, err = w.WriteFile(context.Background(), WriteRequest{Request: request("file", 1), Data: []byte(os.Getenv("W01_DATA"))})
	if errors.Is(err, ErrConflict) {
		os.Exit(24)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestProcessSafeConcurrencyAndOldCheckThenApplyCounterexample(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	// The old two-client pattern allows both checks to pass, then loses one write.
	a, _ := os.ReadFile(filepath.Join(f.root, "file"))
	b, _ := os.ReadFile(filepath.Join(f.root, "file"))
	if !bytes.Equal(a, b) {
		t.Fatal("counterexample setup")
	}
	for _, raw := range [][]byte{[]byte("first"), []byte("second"), []byte("base")} {
		if err := os.WriteFile(filepath.Join(f.root, "file"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmds := make([]*exec.Cmd, 6)
	outputs := make([]bytes.Buffer, len(cmds))
	for i := range cmds {
		cmds[i] = helperCommand(t, f, "", strconv.Itoa(i))
		cmds[i].Stdout = &outputs[i]
		cmds[i].Stderr = &outputs[i]
		if err := cmds[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	ok, conflicts := 0, 0
	for i, cmd := range cmds {
		err := cmd.Wait()
		if err == nil {
			ok++
			continue
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 24 {
			conflicts++
			continue
		}
		t.Fatalf("process %d: %v %s", i, err, outputs[i].String())
	}
	if ok != 1 || conflicts != 5 || inspect(t, f.w).Binding.Revision != 2 {
		t.Fatalf("process winners=%d conflicts=%d", ok, conflicts)
	}
}

func TestRestartAndCorruptJournalFailClosed(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	ctx := context.Background()
	v, err := f.w.WriteFile(ctx, WriteRequest{Request: request("file", 1), Data: []byte("changed")})
	if err != nil {
		t.Fatal(err)
	}
	w, err := Open(ctx, f.c)
	if err != nil {
		t.Fatal(err)
	}
	if got := inspect(t, w); !reflect.DeepEqual(got, v) {
		t.Fatalf("restart changed head: %+v %+v", got, v)
	}
	if err := os.WriteFile(filepath.Join(f.c.StateDir, "state.json"), []byte(`{"schema":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, f.c); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	checkFile(t, f.root, "file", "changed", 0o644)
}

func TestEvidenceObjectCarriesTargetRevisionAndContentParents(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "actual bytes"})
	v := inspect(t, f.w)
	var path, parents string
	if err := f.c.Objects.DB.QueryRow(`SELECT path,parent_hashes FROM provenance_objects WHERE hash=?`, v.Binding.ManifestRef).Scan(&path, &parents); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var obj struct {
		Payload struct {
			Binding  WorkspaceBinding `json:"binding"`
			Revision uint64           `json:"revision"`
			Snapshot Snapshot         `json:"snapshot"`
		}
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	if obj.Payload.Binding.Target != testTarget || obj.Payload.Binding.WorkspaceID != "workspace-1" || obj.Payload.Revision != 1 || obj.Payload.Snapshot.Digest != v.Binding.ManifestDigest || !strings.Contains(parents, findEntry(v.Snapshot, "file").Content.Ref) {
		t.Fatalf("evidence lacks binding/actual content: %s", raw)
	}
}

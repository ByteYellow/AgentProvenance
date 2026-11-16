//go:build linux || darwin

package workspace

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalWriteDuringIntentDoesNotGetOverwritten(t *testing.T) {
	for _, op := range []Operation{Write, Execute} {
		t.Run(string(op), func(t *testing.T) {
			f := newFixture(t, map[string]string{"file": "base"})
			f.w.fault = func(stage string) error {
				if stage == "after_intent" {
					return os.WriteFile(filepath.Join(f.root, "file"), []byte("external wins"), 0o644)
				}
				return nil
			}
			var v View
			var err error
			if op == Write {
				v, err = f.w.WriteFile(context.Background(), WriteRequest{Request: request("file", 1), Data: []byte("must not win")})
			} else {
				v, err = f.w.ObserveExecution(context.Background(), request("", 1), func(context.Context, ExecutionInput) (ExecutionResult, error) {
					t.Fatal("runner called with stale input")
					return ExecutionResult{}, nil
				})
			}
			if !errors.Is(err, ErrConflict) || v.Binding.Revision != 2 || v.LastReceipt.Kind != "external_observation" || v.LastReceipt.Operation != op {
				t.Fatalf("intent conflict: %+v %v", v, err)
			}
			checkFile(t, f.root, "file", "external wins", 0o644)
			checkEvidence(t, f, v)
		})
	}
}

func TestExternalChangeAfterApplyIsNotClaimedAsManagedOutput(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	f.w.fault = func(stage string) error {
		if stage == "after_apply" {
			return os.WriteFile(filepath.Join(f.root, "unrelated"), []byte("external"), 0o644)
		}
		return nil
	}
	v, err := f.w.WriteFile(context.Background(), WriteRequest{Request: request("file", 1), Data: []byte("managed")})
	if !errors.Is(err, ErrChanged) || v.LastReceipt.Outcome != "external_changes_observed" || v.LastReceipt.Claim != "filesystem_observation" || v.LastReceipt.PlannedManifest == v.LastReceipt.OutputManifest {
		t.Fatalf("mixed result: %+v %v", v, err)
	}
	checkFile(t, f.root, "file", "managed", 0o644)
	checkEvidence(t, f, v)
}

func TestGenerationChangeAtIntentAndDuringExecution(t *testing.T) {
	for _, phase := range []string{"intent", "runner"} {
		t.Run(phase, func(t *testing.T) {
			current := testTarget
			f := newFixture(t, map[string]string{"file": "base"}, func(c *Config) { c.CurrentTarget = func(context.Context) (Target, error) { return current, nil } })
			if phase == "intent" {
				f.w.fault = func(stage string) error {
					if stage == "after_intent" {
						current.Generation = "restored"
					}
					return nil
				}
			}
			_, err := f.w.ObserveExecution(context.Background(), request("", 1), func(context.Context, ExecutionInput) (ExecutionResult, error) {
				if phase == "intent" {
					t.Fatal("stale runner called")
				}
				current.Generation = "restored"
				return ExecutionResult{}, nil
			})
			if !errors.Is(err, ErrStaleTarget) || !errors.Is(err, ErrRecovery) {
				t.Fatal(err)
			}
			dir, err := openDir(f.c.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			s, err := loadJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			if s.Pending == nil || s.View.Binding.Revision != 1 {
				t.Fatal("stale generation published a completion")
			}
			checkFile(t, f.root, "file", "base", 0o644)
		})
	}
}

func TestRootReplacementAndStateSymlinksFailClosed(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	if err := os.Rename(f.root, f.root+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, "file"), []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.ReadFile(context.Background(), request("file", 1)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	checkFile(t, f.root, "file", "replacement", 0o644)
	for _, name := range []string{"lock", "state.json"} {
		t.Run(name, func(t *testing.T) {
			g := newFixture(t, map[string]string{"file": "base"})
			outside := filepath.Join(filepath.Dir(g.root), "unrelated")
			if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(g.c.StateDir, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			if _, err := g.w.DeleteFile(context.Background(), request("file", 1)); err == nil {
				t.Fatal("state symlink accepted")
			}
			checkFile(t, filepath.Dir(g.root), "unrelated", "keep", 0o600)
		})
	}
}

func TestByteEntryAndModeLimitsRejectBeforeApply(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "1234"}, func(c *Config) { c.Limits = Limits{FileBytes: 4, TotalBytes: 8, Entries: 2, OutputBytes: 4} })
	ctx := context.Background()
	if _, err := f.w.WriteFile(ctx, WriteRequest{Request: request("second", 1), Data: []byte("5678")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.WriteFile(ctx, WriteRequest{Request: request("third", 2), Data: []byte("x")}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if _, err := f.w.EditFile(ctx, EditRequest{Request: request("file", 2), Old: []byte("1"), New: []byte("long"), Count: 1}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	for _, mode := range []fs.FileMode{0o000, 0o111, 0o200} {
		if _, err := f.w.ChmodFile(ctx, ChmodRequest{Request: request("file", 2), Mode: mode}); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	checkFile(t, f.root, "file", "1234", 0o644)
	if inspect(t, f.w).Binding.Revision != 2 {
		t.Fatal("rejected plan advanced revision")
	}
	if _, err := f.w.WriteFile(ctx, WriteRequest{Request: request("file", 2), Data: []byte("same"), Mode: modePtr(0o600)}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func modePtr(mode fs.FileMode) *fs.FileMode { return &mode }

func TestEvidenceTamperingAndNonDurableDatabaseFailClosed(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	v := inspect(t, f.w)
	var path string
	if err := f.c.Objects.DB.QueryRow(`SELECT path FROM provenance_objects WHERE hash=?`, v.Binding.ManifestRef).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.WriteFile(context.Background(), WriteRequest{Request: request("file", 1), Data: []byte("wrong")}); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	checkFile(t, f.root, "file", "base", 0o644)
	g := newFixture(t, map[string]string{"file": "base"})
	g.c.Objects.DB.SetMaxOpenConns(1)
	if _, err := g.c.Objects.DB.Exec(`PRAGMA synchronous=OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := g.w.ReadFile(context.Background(), request("file", 1)); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestMissingHeadDoesNotResetPublishedRevision(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	if _, err := f.w.WriteFile(context.Background(), WriteRequest{Request: request("file", 1), Data: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.c.StateDir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), f.c); !errors.Is(err, ErrRecovery) {
		t.Fatalf("lost journal reinitialized: %v", err)
	}
	checkFile(t, f.root, "file", "new", 0o644)
}

func TestInterruptedExecutionIsObservedWithoutReplay(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	cmd := helperCommand(t, f, "execute_during", "")
	raw, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("child execution crash: %v %s", err, raw)
	}
	w, err := Open(context.Background(), f.c)
	if err != nil {
		t.Fatal(err)
	}
	v := inspect(t, w)
	if v.LastReceipt.Kind != "recovery_observation" || v.LastReceipt.Operation != Execute || v.LastReceipt.Outcome != "outcome_unknown" || v.LastReceipt.Record != nil {
		t.Fatal(v.LastReceipt)
	}
	checkFile(t, f.root, "ran-once", "once", 0o644)
	if _, err := w.ObserveExecution(context.Background(), request("", 1), func(context.Context, ExecutionInput) (ExecutionResult, error) {
		t.Fatal("old execution replayed")
		return ExecutionResult{}, nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	checkEvidence(t, f, v)
}

func TestExcludedMetadataAndCaseSpellingAreExplicit(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base", ".git/config": "excluded", ".agentprov/log": "excluded"})
	v := inspect(t, f.w)
	if len(v.Snapshot.Entries) != 1 {
		t.Fatal(v.Snapshot.Entries)
	}
	if err := os.WriteFile(filepath.Join(f.root, ".git/config"), []byte("outside observed scope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if inspect(t, f.w).Binding.Revision != 1 {
		t.Fatal("excluded metadata revised workspace")
	}
	if _, err := f.w.RenameFile(context.Background(), RenameRequest{Request: request("file", 1), Destination: "FILE"}); !errors.Is(err, ErrUnsafePath) {
		t.Fatal(err)
	}
	var count int
	if err := f.c.Objects.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("workspace observations generated sensor events")
	}
}

func TestOpenValidationAndUntrustedPaths(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	for _, change := range []func(*Config){
		func(c *Config) { c.Binding.Mode = "snapshot-transfer" }, func(c *Config) { c.Binding.Target.Generation = "" },
		func(c *Config) { c.Binding.AllowedOperations = []Operation{Read, Read} }, func(c *Config) { c.Binding.AllowedOperations = []Operation{"invalid"} },
		func(c *Config) { c.CurrentTarget = nil }, func(c *Config) { c.RunID = "bad\nrun" }, func(c *Config) { c.Limits.FileBytes = 33 << 20 },
		func(c *Config) { c.StateDir = filepath.Join(f.root, "state") }, func(c *Config) { c.Binding.Root = "relative" },
		func(c *Config) { c.Objects.Paths.Root = f.root },
	} {
		c := f.c
		change(&c)
		if _, err := Open(context.Background(), c); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := f.w.EditFile(context.Background(), EditRequest{Request: request("file", 1), Count: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	r := request("file", 1)
	r.ExpectedDigest = "SHA256:" + strings.Repeat("0", 64)
	if _, err := f.w.WriteFile(context.Background(), WriteRequest{Request: r, Data: []byte("bad")}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := f.w.WriteFile(context.Background(), WriteRequest{Request: request("missing/file", 1), Data: []byte("bad")}); !errors.Is(err, ErrUnsafePath) {
		t.Fatal(err)
	}
	if _, err := f.w.ObserveExecution(context.Background(), request("", 1), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := f.w.ObserveExecution(context.Background(), request("", 1), func(context.Context, ExecutionInput) (ExecutionResult, error) {
		return ExecutionResult{Record: &RecordReference{RunID: f.c.RunID, RolloutID: "missing", AttemptID: "missing", BaseSnapshotID: "missing"}}, nil
	}); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	if v := inspect(t, f.w); v.LastReceipt.Outcome != "outcome_unknown" {
		t.Fatal(v.LastReceipt)
	}
	checkFile(t, f.root, "file", "base", 0o644)
}

func TestReadModeBinaryAndCallbackInputAreOwned(t *testing.T) {
	f := newFixture(t, map[string]string{"file": "base"})
	ctx := context.Background()
	v, err := f.w.WriteFile(ctx, WriteRequest{Request: request("binary", 1), Data: []byte{0, 0xff}, Mode: modePtr(0o600)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.w.ReadFile(ctx, request("binary", 2))
	if err != nil || !bytes.Equal(r.Data, []byte{0, 0xff}) {
		t.Fatalf("binary read: %v %v", r, err)
	}
	v, err = f.w.ObserveExecution(ctx, request("", 2), func(_ context.Context, input ExecutionInput) (ExecutionResult, error) {
		input.Binding.AllowedOperations[0] = "corrupt"
		input.Snapshot.Entries[0].Hash = "corrupt"
		return ExecutionResult{ExitCode: 7, Stdout: []byte{0xff}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.LastReceipt.Stdout.State != "binary_omitted" || v.LastReceipt.Stdout.SourceSHA256 != digestBytes([]byte{0xff}) || *v.LastReceipt.ExitCode != 7 {
		t.Fatal(v.LastReceipt)
	}
	checkEvidence(t, f, inspect(t, f.w))
}

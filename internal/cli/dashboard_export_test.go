package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestDashboardExportWritesOnlyNewCompleteZIP(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_URL", "")
	root := t.TempDir()
	db, cleanup, err := openLocalDB(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	_, err = (agentcontext.Service{DB: db, Paths: store.ResolvePaths(filepath.Join(root, "store"))}).Save(context.Background(), "empty-context", agentcontext.Source{ID: "source", Harness: "codex", SessionID: "session", ParserVersion: "fixture/v1", Binding: "explicit"}, nil, agentcontext.Coverage{Status: agentcontext.Empty})
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(root, "share.zip")
	run := func(name string) error {
		cmd := NewRootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--data-dir", filepath.Join(root, "store"), "dashboard", "export", "--run", name, "--output", zipPath})
		return cmd.Execute()
	}
	if err = run("missing"); err == nil {
		t.Fatal("unknown run exported")
	}
	if _, err = os.Stat(zipPath); !os.IsNotExist(err) {
		t.Fatalf("failed export published a file: %v", err)
	}
	if err = run("empty-context"); err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) < 10 {
		t.Fatalf("incomplete ZIP: %d files", len(z.File))
	}
	before, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = run("empty-context"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output overwritten: %v", err)
	}
	after, err := os.ReadFile(zipPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing output changed")
	}
}

func TestDashboardExportSelectionFlags(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_URL", "")
	root := t.TempDir()
	dataDir := filepath.Join(root, "store")
	db, cleanup, err := openLocalDB(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	svc := agentcontext.Service{DB: db, Paths: store.ResolvePaths(dataDir)}
	for _, session := range []string{"first", "second"} {
		body := "recorded " + session
		if _, err := svc.Save(context.Background(), "run", agentcontext.Source{Harness: "codex", SessionID: session, ParserVersion: "fixture/v1", Binding: "explicit"},
			[]agentcontext.Record{{Key: "message", Kind: "message", Body: &body}}, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, scope string
		args        []string
		entries     int
		invalid     bool
	}{
		{name: "session", scope: "session", args: []string{"--harness", "codex", "--session", "first"}, entries: 1},
		{name: "category", scope: "whole_run", args: []string{"--exclude-category", "messages"}},
		{name: "missing-harness", args: []string{"--session", "first"}, invalid: true},
		{name: "unknown-record", args: []string{"--exclude-record", "entry/absent"}, invalid: true},
		{name: "unknown-category", args: []string{"--exclude-category", "unknown"}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(root, tc.name+".zip")
			cmd := NewRootCommand()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(append([]string{"--data-dir", dataDir, "dashboard", "export", "--run", "run", "--output", file}, tc.args...))
			err := cmd.Execute()
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid selection succeeded")
				}
				if _, err := os.Stat(file); !os.IsNotExist(err) {
					t.Fatal("failed selection published a ZIP")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "scope="+tc.scope) {
				t.Fatalf("reported selection: %s", out.String())
			}
			z, err := zip.OpenReader(file)
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			r, err := z.Open("export-inventory.json")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			data, err := io.ReadAll(r)
			var inventory dashboard.ReplayInventory
			if err != nil || json.Unmarshal(data, &inventory) != nil || inventory.Scope != tc.scope || inventory.Contents.ContextEntries != tc.entries {
				t.Fatalf("selection inventory: %+v %v", inventory, err)
			}
		})
	}
}

func TestDashboardExportSelectionFile(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_URL", "")
	root := t.TempDir()
	dataDir := filepath.Join(root, "store")
	db, cleanup, err := openLocalDB(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	svc := agentcontext.Service{DB: db, Paths: store.ResolvePaths(dataDir)}
	for _, run := range []string{"caller", "worker", "unselected"} {
		body := "saved " + run
		if _, err := svc.Save(context.Background(), run, agentcontext.Source{Harness: "codex", SessionID: "session", ParserVersion: "fixture/v1", Binding: "explicit"},
			[]agentcontext.Record{{Key: "message", Kind: "message", Body: &body}}, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
			t.Fatal(err)
		}
	}
	selected := `[{"run_id":"caller","scope":"whole_run"},{"run_id":"worker","scope":"session","harness":"codex","session_id":"session"}]`
	for _, tc := range []struct {
		name, data string
		args       []string
		valid      bool
	}{
		{name: "two-runs", data: selected, valid: true},
		{name: "mixed-run", data: selected, args: []string{"--run", "caller"}},
		{name: "mixed-exclusion", data: selected, args: []string{"--exclude-category", "messages"}},
		{name: "mixed-session", data: selected, args: []string{"--session", "session"}},
		{name: "missing-second", data: strings.ReplaceAll(selected, "worker", "absent")},
		{name: "duplicate", data: strings.ReplaceAll(selected, "worker", "caller")},
		{name: "empty", data: "[]"},
		{name: "null", data: "null"},
		{name: "object", data: `{}`},
		{name: "unknown-field", data: `[{"run_id":"caller","scope":"whole_run","include":"all"}]`},
		{name: "trailing-json", data: selected + `{}`},
		{name: "oversize", data: strings.Repeat(" ", 1<<20) + selected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, output := filepath.Join(root, tc.name+".json"), filepath.Join(root, tc.name+".zip")
			if err := os.WriteFile(input, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := NewRootCommand()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(append([]string{"--data-dir", dataDir, "dashboard", "export", "--selection-file", input, "--output", output}, tc.args...))
			err := cmd.Execute()
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid export succeeded")
				}
				if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
					t.Fatal("failed export published a ZIP")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "scope=run_set") {
				t.Fatal(out.String())
			}
			z, err := zip.OpenReader(output)
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			r, err := z.Open("export-inventory.json")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var inventory dashboard.ReplayInventory
			if err := json.NewDecoder(r).Decode(&inventory); err != nil {
				t.Fatal(err)
			}
			if inventory.Scope != "run_set" || len(inventory.Runs) != 2 || inventory.Runs[0].RunID != "caller" || inventory.Runs[1].RunID != "worker" || inventory.Contents.ContextEntries != 2 {
				t.Fatalf("unexpected set: %+v", inventory)
			}
		})
	}
}

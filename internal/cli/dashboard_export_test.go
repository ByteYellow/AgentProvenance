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

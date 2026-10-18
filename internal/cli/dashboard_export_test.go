package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
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

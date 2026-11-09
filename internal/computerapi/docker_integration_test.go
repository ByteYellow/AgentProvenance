package computerapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/control"
	"github.com/byteyellow/agentprovenance/internal/store"
	runtimeplane "github.com/byteyellow/agentprovenance/internal/substrate/runtime"
	"github.com/byteyellow/agentprovenance/internal/substrate/session"
)

func TestDockerComputerWorkspace(t *testing.T) {
	if os.Getenv("AGENTPROV_DOCKER_TEST_IMAGE") != "python:3-slim" {
		t.Skip("set AGENTPROV_DOCKER_TEST_IMAGE=python:3-slim for the Docker integration test")
	}
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	driver, err := runtimeplane.NewDockerDriver(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Runtime.Client.Close() })
	controller := control.Service{DB: db, Paths: paths, Driver: driver}
	taskPath := filepath.Join(root, "task.yaml")
	if err := os.WriteFile(taskPath, []byte("run_id: workspace-test\nimage: python:3-slim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lease, err := controller.CreateLease(taskPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := controller.CreateSession(lease)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controller.RemoveSession(id); err != nil {
			t.Error(err)
		}
	})
	api := Service{DB: db, Paths: paths}
	if _, err := api.WriteFile(id, "task.py", "from pathlib import Path\nPath('result.txt').write_text('answer=42\\n')\n", "write"); err != nil {
		t.Fatal(err)
	}
	process, _, err := api.Call(id, "shell", "exec", map[string]string{"command": "python3 task.py"}, "build", false)
	if err != nil || process == "" {
		t.Fatalf("call: process=%q err=%v", process, err)
	}
	body, _, err := api.ReadFile(id, "result.txt", "read")
	if err != nil || body != "answer=42\n" {
		t.Fatalf("read: %q %v", body, err)
	}
	matches, _, err := api.Search(id, "answer=42", "search")
	if err != nil || len(matches) == 0 {
		t.Fatalf("search: %v %v", matches, err)
	}
	artifact, _, err := api.ExportArtifact(id, "result.txt", "build result.txt", "export")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(artifact)
	if err != nil || string(raw) != body || !strings.HasPrefix(artifact, paths.Artifacts+string(os.PathSeparator)) {
		t.Fatalf("export: %q %v", raw, err)
	}
	if err := controller.StopSession(id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := api.Call(id, "shell", "exec", map[string]string{"command": "true"}, "stopped", false); !errors.Is(err, session.ErrSessionNotRunning) {
		t.Fatalf("stopped session call = %v", err)
	}
}

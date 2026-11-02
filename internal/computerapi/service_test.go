package computerapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/substrate/session"
)

func newTestService(t *testing.T) (Service, string) {
	t.Helper()
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-t', 'run-t', '', '', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(paths.Workspaces, "sbx-t")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "note.txt"), []byte("canary-payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, runtime, status, startup_cold_ms, created_at, updated_at)
		VALUES ('sbx-t', 'lease-t', 'run-t', 'ctr-t', ?, 'docker', 'running', 0, ?, ?)`, workspace, now, now); err != nil {
		t.Fatal(err)
	}
	return Service{DB: db, Paths: paths}, workspace
}

func TestExportArtifactWritesWithinArtifactsDirWithTightPerms(t *testing.T) {
	svc, _ := newTestService(t)

	ref, _, err := svc.ExportArtifact("sbx-t", "/workspace/note.txt", "note.txt", "tool-t")
	if err != nil {
		t.Fatal(err)
	}
	artifactsRoot := filepath.Clean(svc.Paths.Artifacts)
	if filepath.Clean(ref) == artifactsRoot || !strings.HasPrefix(filepath.Clean(ref), artifactsRoot+string(os.PathSeparator)) {
		t.Fatalf("artifact %q escaped artifacts dir %q", ref, artifactsRoot)
	}
	body, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "canary-payload" {
		t.Fatalf("content = %q, want canary-payload", body)
	}
	info, err := os.Stat(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("artifact perms = %o, want 600", got)
	}
}

func TestExportArtifactDefaultsToBaseName(t *testing.T) {
	svc, _ := newTestService(t)

	ref, _, err := svc.ExportArtifact("sbx-t", "/workspace/note.txt", "", "tool-t")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.Base(ref), "-note.txt") {
		t.Fatalf("default name = %q, want suffix -note.txt", filepath.Base(ref))
	}
}

func TestExportArtifactRejectsTraversalNames(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		// 注：含分隔符的名字先被分隔符检查拦截，reason 以首条为准
		{"../../..", "path separator"},
		{"a/../../x", "path separator"},
		{"..", "parent-directory"},
		// 注：空串在本层语义是“回退为源文件名”（CLI 不传 --name 的默认用法依赖此行为），
		// 回退结果同样必须过 sanitizeArtifactName；空串拒绝契约在 TestSanitizeArtifactNameRejectsEmpty 锁定。
		{".", "dot"},
		{".hidden", "dot"},
		{"x/../y", "path separator"},
		{"/abs/path", "path separator"},
		{`back\slash`, "path separator"},
		{"space name", "outside [A-Za-z0-9._-]"},
		{"..dot", "parent-directory"},
	}
	for _, tc := range cases {
		t.Run(quoteOrDefault(tc.name), func(t *testing.T) {
			svc, _ := newTestService(t)
			ref, _, err := svc.ExportArtifact("sbx-t", "/workspace/note.txt", tc.name, "tool-t")
			if !errors.Is(err, ErrInvalidArtifactName) {
				t.Fatalf("name %q: err = %v, want ErrInvalidArtifactName", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("name %q: error %v missing reason %q", tc.name, err, tc.want)
			}
			if ref != "" {
				t.Fatalf("name %q: returned artifact ref %q on rejection", tc.name, ref)
			}
			entries, err := os.ReadDir(svc.Paths.Artifacts)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("name %q: artifacts dir not empty: %v", tc.name, entries)
			}
		})
	}
}

func TestExportArtifactNeverEscapesEvenWithAbsorbedPrefix(t *testing.T) {
	// 防御性复核：假设白名单被绕过，join+Clean 后的落点校验也必须拦截。
	if err := ensureInsideArtifacts("/tmp/ap-data/artifacts", filepath.Join("/tmp/ap-data/artifacts", "artifact-1-../..")); err == nil {
		t.Fatalf("absorbed-prefix traversal must be rejected by ensureInsideArtifacts")
	}
	if err := ensureInsideArtifacts("/tmp/ap-data/artifacts", "/tmp/ap-data/artifacts"); err == nil {
		t.Fatalf("artifacts dir itself must be rejected as destination")
	}
	if err := ensureInsideArtifacts("/tmp/ap-data/artifacts", filepath.Join("/tmp/ap-data/artifacts", "artifact-1-note.txt")); err != nil {
		t.Fatalf("legit destination rejected: %v", err)
	}
}

func TestSanitizeArtifactNameRejectsEmpty(t *testing.T) {
	if _, err := sanitizeArtifactName(""); !errors.Is(err, ErrInvalidArtifactName) {
		t.Fatalf("empty name: err = %v, want ErrInvalidArtifactName", err)
	}
	for _, ok := range []string{"note.txt", "my-file_1.tar.gz", "A9_x-y.z"} {
		if _, err := sanitizeArtifactName(ok); err != nil {
			t.Fatalf("legit name %q rejected: %v", ok, err)
		}
	}
}

func TestCallRequiresRunnableSessionBeforeContainerAccess(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := svc.DB.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = 'sbx-t'`, now); err != nil {
		t.Fatal(err)
	}

	_, _, err := svc.Call("sbx-t", "shell", "exec", map[string]string{"command": "id"}, "tool-x", false)
	if !errors.Is(err, session.ErrSessionNotRunning) {
		t.Fatalf("Call on stopped session: err = %v, want session.ErrSessionNotRunning", err)
	}

	_, _, err = svc.Call("sbx-missing", "shell", "exec", map[string]string{"command": "id"}, "tool-x", false)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("Call on missing session: err = %v, want session.ErrSessionNotFound", err)
	}
	if strings.Contains(err.Error(), "sql: no rows") {
		t.Fatalf("Call on missing session leaks driver error: %v", err)
	}
}

func quoteOrDefault(name string) string {
	if name == "" {
		return "empty"
	}
	return name
}

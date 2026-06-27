package state

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestCreateSnapshotAndForkWorkspaces(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	workspace := filepath.Join(paths.Workspaces, "sbx-test")
	if err := os.MkdirAll(filepath.Join(workspace, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "nested", "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	insertSession(t, db, workspace)

	svc := Service{DB: db, Paths: paths}
	snapshotID, manifest, snapshotCreateMS, err := svc.CreateDirectorySnapshot("sbx-test", "/workspace", "ready")
	if err != nil {
		t.Fatal(err)
	}
	if snapshotID == "" || manifest.Files != 1 || manifest.Bytes != 5 {
		t.Fatalf("unexpected snapshot result id=%q manifest=%+v", snapshotID, manifest)
	}
	if snapshotCreateMS < 0 {
		t.Fatalf("snapshotCreateMS = %d, want >= 0", snapshotCreateMS)
	}

	forks, err := svc.Fork("ready", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(forks) != 2 {
		t.Fatalf("fork count = %d, want 2", len(forks))
	}
	for _, fork := range forks {
		if fork.AttemptID == "" || fork.WorkspacePath == "" || fork.ForkMS < 0 {
			t.Fatalf("unexpected fork result: %+v", fork)
		}
		b, err := os.ReadFile(filepath.Join(fork.WorkspacePath, "nested", "hello.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "hello" {
			t.Fatalf("forked file = %q, want hello", string(b))
		}
	}
}

func TestCreateStackRecordsLineage(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	taskPath := filepath.Join(root, "task.yaml")
	if err := os.WriteFile(taskPath, []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.TemplateSnapshotID == "" || result.ReadySnapshotID == "" || result.Attempt.AttemptID == "" {
		t.Fatalf("unexpected stack result: %+v", result)
	}
	ready, lineage, err := Service{DB: db, Paths: paths}.InspectSnapshot(result.ReadySnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Kind != "ready" || ready.ParentID != result.TemplateSnapshotID || ready.Bytes == 0 {
		t.Fatalf("unexpected ready snapshot: %+v", ready)
	}
	if len(lineage) != 2 || lineage[1].Kind != "template" {
		t.Fatalf("lineage = %+v, want ready -> template", lineage)
	}
}

func TestCreateStackFromTemplateRecordsBundleLineage(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	templateID := "tmpl-test"
	templateDir := filepath.Join(paths.Templates, templateID)
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(templateDir, "task.yaml"), []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(templateDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.Exec(`INSERT INTO templates (id, name, task_path, image, risk_tier, network_mode, manifest_hash, bytes, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?)`,
		templateID, "test-template", filepath.Join(root, "task.yaml"), "alpine:3.20", "medium", "allowlist", manifest.Hash, manifest.Bytes, now)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Service{DB: db, Paths: paths}.CreateStackFromTemplate("test-template")
	if err != nil {
		t.Fatal(err)
	}
	if result.TemplateSnapshotID != templateID {
		t.Fatalf("template snapshot = %s, want %s", result.TemplateSnapshotID, templateID)
	}
	ready, lineage, err := Service{DB: db, Paths: paths}.InspectSnapshot(result.ReadySnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if ready.ParentID != templateID || len(lineage) != 2 || lineage[1].ID != templateID {
		t.Fatalf("unexpected lineage: ready=%+v lineage=%+v", ready, lineage)
	}
}

func TestAnalyzeIOProfileDetectsHotMetadataPaths(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		filepath.Join(root, ".git", "objects", "aa", "obj"),
		filepath.Join(root, "node_modules", "pkg", "index.js"),
		filepath.Join(root, ".venv", "lib", "site-packages", "pkg.py"),
		filepath.Join(root, "src", "main.go"),
	}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	profile, err := AnalyzeIOProfile(root)
	if err != nil {
		t.Fatal(err)
	}
	if profile.CopyUpRisk != "high" {
		t.Fatalf("copy_up_risk=%s, want high", profile.CopyUpRisk)
	}
	if profile.MetadataOpsEstimate <= int64(len(paths)) {
		t.Fatalf("metadata estimate did not account for hot paths: %+v", profile)
	}
	for _, want := range []string{".git", ".venv", "node_modules"} {
		if !strings.Contains(strings.Join(profile.HotMetadataPaths, ","), want) {
			t.Fatalf("hot paths %+v missing %s", profile.HotMetadataPaths, want)
		}
	}
}

func TestPlanWithPolicySelectsSmallestDelta(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	insertPlannerSnapshot(t, db, paths, plannerSnapshot{
		ID:             "snap-large-delta",
		Name:           "ready",
		Bytes:          10,
		DeltaAdded:     20,
		DeltaModified:  4,
		CreatedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		CopyUpRisk:     "medium",
		MetadataOps:    24,
		SemanticType:   "directory",
		PhysicalType:   "copy",
		UpperdirDevice: "local",
	})
	insertPlannerSnapshot(t, db, paths, plannerSnapshot{
		ID:             "snap-small-delta",
		Name:           "ready",
		Bytes:          10,
		DeltaAdded:     1,
		CreatedAt:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		CopyUpRisk:     "low",
		MetadataOps:    1,
		SemanticType:   "directory",
		PhysicalType:   "copy",
		UpperdirDevice: "local",
	})

	plan, err := Service{DB: db, Paths: paths}.PlanWithPolicy("ready", "smallest-delta", false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SnapshotID != "snap-small-delta" {
		t.Fatalf("snapshot=%s, want snap-small-delta; plan=%+v", plan.SnapshotID, plan)
	}
	if plan.SelectedPolicy != "smallest-delta" || plan.CandidateCount != 2 || plan.DeltaFilesAdded != 1 {
		t.Fatalf("unexpected planner details: %+v", plan)
	}
}

func TestPlanWithPolicyRejectsTaintedCandidate(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	insertPlannerSnapshot(t, db, paths, plannerSnapshot{
		ID:           "snap-tainted",
		Name:         "ready",
		Bytes:        1,
		CreatedAt:    time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:       "tainted",
		Tainted:      true,
		SemanticType: "directory",
		PhysicalType: "copy",
	})
	insertPlannerSnapshot(t, db, paths, plannerSnapshot{
		ID:           "snap-clean",
		Name:         "ready",
		Bytes:        1,
		CreatedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:       "ready",
		SemanticType: "directory",
		PhysicalType: "copy",
	})

	plan, err := Service{DB: db, Paths: paths}.PlanWithPolicy("ready", "latest-ready", true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SnapshotID != "snap-clean" {
		t.Fatalf("snapshot=%s, want snap-clean; plan=%+v", plan.SnapshotID, plan)
	}
	if plan.CandidateCount != 2 {
		t.Fatalf("candidate_count=%d, want 2", plan.CandidateCount)
	}
}

func insertSession(t *testing.T, db *sql.DB, workspace string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-test', 'run-test', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('sbx-test', 'lease-test', 'run-test', 'container-test', ?, 'running', ?, ?)`, workspace, now, now)
	if err != nil {
		t.Fatal(err)
	}
}

type plannerSnapshot struct {
	ID             string
	Name           string
	Bytes          int64
	DeltaAdded     int64
	DeltaModified  int64
	DeltaDeleted   int64
	CreatedAt      time.Time
	Status         string
	Tainted        bool
	CopyUpRisk     string
	MetadataOps    int64
	SemanticType   string
	PhysicalType   string
	UpperdirDevice string
}

func insertPlannerSnapshot(t *testing.T, db *sql.DB, paths store.Paths, snapshot plannerSnapshot) {
	t.Helper()
	if snapshot.Status == "" {
		snapshot.Status = "ready"
	}
	if snapshot.CopyUpRisk == "" {
		snapshot.CopyUpRisk = "low"
	}
	if snapshot.SemanticType == "" {
		snapshot.SemanticType = "directory"
	}
	if snapshot.PhysicalType == "" {
		snapshot.PhysicalType = "copy"
	}
	snapshotDir := filepath.Join(paths.Snapshots, snapshot.ID)
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshotDir, "file.txt"), []byte(snapshot.ID), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(snapshotDir)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := snapshot.CreatedAt.UTC().Format(time.RFC3339Nano)
	tainted := 0
	if snapshot.Tainted {
		tainted = 1
	}
	_, err = db.Exec(`INSERT INTO snapshots (
			id, name, kind, source, path, manifest_hash, file_count, bytes,
			delta_files_added, delta_files_modified, delta_files_deleted,
			snapshot_semantic_type, snapshot_physical_type, logical_bytes, physical_bytes,
			dirty_bytes_estimate, inode_estimate, storage_amplification_ratio,
			metadata_ops_estimate, copy_up_risk, upperdir_device, tainted, status, created_at
		) VALUES (?, ?, 'ready', 'test', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
		snapshot.ID, snapshot.Name, snapshotDir, manifest.Hash, manifest.Files, snapshot.Bytes,
		snapshot.DeltaAdded, snapshot.DeltaModified, snapshot.DeltaDeleted,
		snapshot.SemanticType, snapshot.PhysicalType, snapshot.Bytes, snapshot.Bytes,
		snapshot.Bytes, manifest.Files, snapshot.MetadataOps, snapshot.CopyUpRisk,
		snapshot.UpperdirDevice, tainted, snapshot.Status, createdAt)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCopyDirFilteredSkipsDstSubtreeAndFiltered(t *testing.T) {
	src := t.TempDir()
	// A normal file, plus a data dir living INSIDE the workdir whose snapshot
	// store is the copy destination (the record self-recursion case).
	if err := os.WriteFile(filepath.Join(src, "keep.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(src, ".agentprov", "snapshots")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".agentprov", "agentprov.db"), []byte("DB"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dataDir, "snap-base")

	skip := func(rel string) bool {
		return rel == ".git" || strings.HasPrefix(rel, ".git/") ||
			rel == ".agentprov" || strings.HasPrefix(rel, ".agentprov")
	}
	// Must not crash with "file name too long" from recursing into its own dst.
	if err := CopyDirFiltered(src, dst, skip); err != nil {
		t.Fatalf("CopyDirFiltered failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "keep.txt")); err != nil {
		t.Fatalf("expected keep.txt copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".agentprov")); !os.IsNotExist(err) {
		t.Fatalf("expected .agentprov excluded from snapshot, stat err=%v", err)
	}
}

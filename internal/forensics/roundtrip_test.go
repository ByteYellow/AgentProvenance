package forensics_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// TestForensicsBundleRoundTripIsPortable is the fidelity oracle the lens-diff
// bash harness structurally cannot be: it captures a run in store A (with a real
// object blob + a snapshot file on disk), exports a bundle, imports into store B
// at a DIFFERENT root, and verifies the artifact CONTENT survives byte-for-byte
// and resolves under B's root — the "replay anywhere" property nothing else checks
// (the lens never reads object/snapshot bytes or their absolute paths).
func TestForensicsBundleRoundTripIsPortable(t *testing.T) {
	const runID = "run-roundtrip"
	objContent := []byte(`{"schema":"agentprov.provenance.object.v1","artifact":"snake.py"}`)
	snapFileContent := []byte("print('snake')\n")

	// --- capture: store A ---
	pathsA := mustInit(t, filepath.Join(t.TempDir(), "A"))
	dbA := mustOpen(t, pathsA)
	objHash := writeObjectBlob(t, dbA, pathsA, runID, objContent)
	writeSnapshot(t, dbA, pathsA, runID, "snap-rt", "app.py", snapFileContent)

	bundlePath, err := forensics.Service{DB: dbA, Paths: pathsA}.Export(runID)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	_ = dbA.Close()

	// --- replay: store B at a different root ---
	pathsB := mustInit(t, filepath.Join(t.TempDir(), "B"))
	dbB := mustOpen(t, pathsB)
	defer dbB.Close()
	info, err := (forensics.Service{DB: dbB, Paths: pathsB}).ImportBundle(bundlePath)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	// (a) row counts + content tallies
	if info.ObjectBlobs != 1 || info.SnapshotFiles != 1 || info.Omitted != 0 {
		t.Fatalf("import tallies: objects=%d snapshot_files=%d omitted=%d, want 1/1/0", info.ObjectBlobs, info.SnapshotFiles, info.Omitted)
	}
	if got := countRows(t, dbB, "provenance_objects", runID); got != 1 {
		t.Fatalf("provenance_objects in B = %d, want 1", got)
	}

	// (b)+(c) object blob: path rewritten under B's root, file exists, bytes identical
	var objPathB string
	if err := dbB.QueryRow(`SELECT path FROM provenance_objects WHERE hash = ?`, objHash).Scan(&objPathB); err != nil {
		t.Fatalf("query object path: %v", err)
	}
	if !strings.HasPrefix(objPathB, pathsB.Root) {
		t.Fatalf("object path %q not under B root %q (not portable)", objPathB, pathsB.Root)
	}
	gotObj, err := os.ReadFile(objPathB)
	if err != nil {
		t.Fatalf("object blob not on disk under B: %v", err)
	}
	if string(gotObj) != string(objContent) {
		t.Fatalf("object blob content mismatch after replay")
	}
	if sum := sha256.Sum256(gotObj); "sha256:"+hex.EncodeToString(sum[:]) != objHash {
		t.Fatalf("replayed object blob fails its own content hash")
	}

	// (b)+(c) snapshot file: under B's (rewritten) snapshot path, bytes identical
	var snapPathB string
	if err := dbB.QueryRow(`SELECT path FROM snapshots WHERE id = ?`, "snap-rt").Scan(&snapPathB); err != nil {
		t.Fatalf("query snapshot path: %v", err)
	}
	if !strings.HasPrefix(snapPathB, pathsB.Root) {
		t.Fatalf("snapshot path %q not under B root %q", snapPathB, pathsB.Root)
	}
	gotSnap, err := os.ReadFile(filepath.Join(snapPathB, "app.py"))
	if err != nil {
		t.Fatalf("snapshot file not on disk under B: %v", err)
	}
	if string(gotSnap) != string(snapFileContent) {
		t.Fatalf("snapshot file content mismatch after replay")
	}
}

// TestForensicsImportRejectsTamperedObject codifies verify-before-commit: a bundle
// whose embedded object content no longer matches its declared hash must be refused
// outright (a tampered captured artifact can never enter the store).
func TestForensicsImportRejectsTamperedObject(t *testing.T) {
	const runID = "run-tamper"
	pathsA := mustInit(t, filepath.Join(t.TempDir(), "A"))
	dbA := mustOpen(t, pathsA)
	writeObjectBlob(t, dbA, pathsA, runID, []byte(`{"v":1}`))
	bundlePath, err := forensics.Service{DB: dbA, Paths: pathsA}.Export(runID)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	_ = dbA.Close()

	// Flip a byte in the embedded blob content (hash now mismatches).
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	blobs := bundle["object_blobs"].([]any)
	blob := blobs[0].(map[string]any)
	content, _ := base64.StdEncoding.DecodeString(blob["content_b64"].(string))
	content[0] ^= 0xFF
	blob["content_b64"] = base64.StdEncoding.EncodeToString(content)
	tampered, _ := json.MarshalIndent(bundle, "", "  ")
	tamperedPath := filepath.Join(filepath.Dir(bundlePath), "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	pathsB := mustInit(t, filepath.Join(t.TempDir(), "B"))
	dbB := mustOpen(t, pathsB)
	defer dbB.Close()
	_, err = (forensics.Service{DB: dbB, Paths: pathsB}).ImportBundle(tamperedPath)
	if err == nil {
		t.Fatal("import accepted a tampered object blob; want hash-mismatch error")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("error %q does not name a hash mismatch", err)
	}
	// The tampered run must not have leaked into the store.
	if got := countRows(t, dbB, "provenance_objects", runID); got != 0 {
		t.Fatalf("tampered import leaked %d provenance_objects rows", got)
	}
}

// --- fixture helpers ---

func mustInit(t *testing.T, root string) store.Paths {
	t.Helper()
	paths, err := store.Init(root)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	return paths
}

func mustOpen(t *testing.T, paths store.Paths) *sql.DB {
	t.Helper()
	db, err := store.Open(paths)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return db
}

// writeObjectBlob writes a content-addressed blob to the store's object dir and
// inserts its provenance_objects row, returning the hash.
func writeObjectBlob(t *testing.T, db *sql.DB, paths store.Paths, runID string, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	clean := hex.EncodeToString(sum[:])
	hash := "sha256:" + clean
	blobPath := filepath.Join(paths.Provenance, "objects", "sha256", clean[:2], clean+".json")
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blobPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO provenance_objects (hash, object_type, source_id, run_id, path, size_bytes, created_at)
		VALUES (?, 'artifact', ?, ?, ?, ?, '2026-06-29T00:00:00Z')`, hash, "src-"+clean[:8], runID, blobPath, len(content)); err != nil {
		t.Fatalf("insert provenance_object: %v", err)
	}
	return hash
}

// writeSnapshot creates a session-scoped snapshot dir with one file and inserts
// the lease/session/snapshot rows so the export's run-scoping picks it up.
func writeSnapshot(t *testing.T, db *sql.DB, paths store.Paths, runID, snapID, fileName string, content []byte) {
	t.Helper()
	const ts = "2026-06-29T00:00:00Z"
	if _, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-rt', ?, 'task.yaml', '{}', 'allocated', ?, ?)`, runID, ts, ts); err != nil {
		t.Fatalf("insert lease: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sessions (id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-rt', 'lease-rt', ?, '/tmp/ws', 'running', ?, ?)`, runID, ts, ts); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	snapDir := filepath.Join(paths.Snapshots, snapID)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, fileName), content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO snapshots (id, session_id, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES (?, 'session-rt', 'directory', 'session', ?, 'manifest-rt', 1, ?, 'ready', ?)`, snapID, snapDir, len(content), ts); err != nil {
		t.Fatalf("insert snapshot: %v", err)
	}
}

func countRows(t *testing.T, db *sql.DB, table, runID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM "+table+" WHERE run_id = ?", runID).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

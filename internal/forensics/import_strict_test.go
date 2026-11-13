package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
)

func strictFixture(t *testing.T) (forensics.Service, string, string) {
	t.Helper()
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	t.Cleanup(func() { db.Close() })
	const run = "remote-run"
	writeObjectBlob(t, db, paths, run, []byte(`{"saved":"original"}`))
	writeSnapshot(t, db, paths, run, "snapshot", "result.txt", []byte("original result"))
	if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at,pid)
		VALUES('event',?,'fixture','exec_start','{"result":"original"}','2026-11-14T00:00:00Z',9007199254740993)`, run); err != nil {
		t.Fatal(err)
	}
	path, err := (forensics.Service{DB: db, Paths: paths}).Export(run)
	if err != nil {
		t.Fatal(err)
	}
	dest := mustInit(t, filepath.Join(t.TempDir(), "接收端"))
	destDB := mustOpen(t, dest)
	t.Cleanup(func() { destDB.Close() })
	return forensics.Service{DB: destDB, Paths: dest}, path, run
}

func alterBundle(t *testing.T, path string, change func(map[string]any)) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	change(bundle)
	raw, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "changed.json")
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestStrictImportRejectsReplacement(t *testing.T) {
	svc, path, run := strictFixture(t)
	if _, err := svc.ImportBundleStrict(context.Background(), path, run); err != nil {
		t.Fatal(err)
	}
	changed := alterBundle(t, path, func(bundle map[string]any) {
		bundle["events"].([]any)[0].(map[string]any)["payload"] = `{"result":"changed"}`
	})
	if _, err := svc.ImportBundleStrict(context.Background(), changed, run); !errors.Is(err, forensics.ErrBundleConflict) {
		t.Fatalf("same ID with changed evidence must conflict: %v", err)
	}
	var payload string
	if err := svc.DB.QueryRow(`SELECT payload FROM events WHERE id='event' AND run_id=?`, run).Scan(&payload); err != nil || payload != `{"result":"original"}` {
		t.Fatalf("stored evidence was replaced: %q %v", payload, err)
	}
}

func TestStrictImportPortableConcurrentAndExact(t *testing.T) {
	svc, path, run := strictFixture(t)
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.ImportBundleStrict(context.Background(), path, run)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	var pid int64
	if err := svc.DB.QueryRow(`SELECT COUNT(*),MAX(pid) FROM events`).Scan(&count, &pid); err != nil || count != 1 || pid != 9007199254740993 {
		t.Fatalf("replay duplicated rows or rounded an integer: %d %d %v", count, pid, err)
	}
	var snapshot string
	if err := svc.DB.QueryRow(`SELECT path FROM snapshots WHERE id='snapshot'`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(snapshot, "result.txt"))
	if err != nil || string(data) != "original result" || !strings.HasPrefix(snapshot, svc.Paths.Artifacts+string(filepath.Separator)) {
		t.Fatalf("portable content: %q %q %v", snapshot, data, err)
	}
	// A new serialization/export timestamp still carries the same evidence.
	changed := alterBundle(t, path, func(bundle map[string]any) { bundle["exported_at"] = "2026-11-14T01:00:00Z" })
	if _, err := svc.ImportBundleStrict(context.Background(), changed, run); err != nil {
		t.Fatal(err)
	}
}

func TestStrictImportConflictRollsBackWholeProjection(t *testing.T) {
	svc, path, run := strictFixture(t)
	if _, err := svc.ImportBundleStrict(context.Background(), path, run); err != nil {
		t.Fatal(err)
	}
	changed := alterBundle(t, path, func(bundle map[string]any) {
		bundle["events"] = append(bundle["events"].([]any), map[string]any{"id": "new-event", "run_id": run,
			"source": "fixture", "event_type": "exec_end", "payload": "{}", "created_at": "2026-11-14T01:00:00Z"})
		bundle["provenance_objects"].([]any)[0].(map[string]any)["source_id"] = "different-source"
	})
	if _, err := svc.ImportBundleStrict(context.Background(), changed, run); !errors.Is(err, forensics.ErrBundleConflict) {
		t.Fatalf("expected object identity conflict: %v", err)
	}
	if got := countRows(t, svc.DB, "events", run); got != 1 {
		t.Fatalf("partial import committed %d events", got)
	}
}

func TestStrictImportRejectsIncompleteAndConflictingContent(t *testing.T) {
	for _, kind := range []string{"foreign_run", "missing_object", "duplicate_event", "snapshot_identity", "snapshot_changed", "missing_id", "null_id", "object_size", "orphan_snapshot", "orphan_object", "missing_body"} {
		t.Run(kind, func(t *testing.T) {
			svc, path, run := strictFixture(t)
			if kind == "snapshot_changed" {
				if _, err := svc.ImportBundleStrict(context.Background(), path, run); err != nil {
					t.Fatal(err)
				}
			}
			changed := alterBundle(t, path, func(bundle map[string]any) {
				switch kind {
				case "foreign_run":
					bundle["events"].([]any)[0].(map[string]any)["run_id"] = "another-run"
				case "missing_object":
					delete(bundle, "object_blobs")
				case "duplicate_event":
					bundle["events"] = append(bundle["events"].([]any), map[string]any{"id": "event", "run_id": run, "payload": "changed"})
				case "snapshot_identity":
					bundle["snapshots"].([]any)[0].(map[string]any)["id"] = "../escape"
				case "snapshot_changed":
					bundle["snapshot_files"].([]any)[0].(map[string]any)["content_b64"] = base64.StdEncoding.EncodeToString([]byte("altered content"))
				case "missing_id":
					delete(bundle["events"].([]any)[0].(map[string]any), "id")
				case "null_id":
					bundle["events"].([]any)[0].(map[string]any)["id"] = nil
				case "object_size":
					bundle["provenance_objects"].([]any)[0].(map[string]any)["size_bytes"] = 999
				case "orphan_snapshot":
					bundle["snapshot_files"].([]any)[0].(map[string]any)["snapshot_id"] = "other-snapshot"
				case "orphan_object":
					delete(bundle, "provenance_objects")
				case "missing_body":
					delete(bundle["snapshot_files"].([]any)[0].(map[string]any), "content_b64")
				}
			})
			if _, err := svc.ImportBundleStrict(context.Background(), changed, run); err == nil {
				t.Fatal("invalid or conflicting bundle accepted")
			}
			expected := 0
			if kind == "snapshot_changed" {
				expected = 1
			}
			if countRows(t, svc.DB, "events", run) != expected {
				t.Fatal("failed import changed evidence")
			}
		})
	}
}

func TestStrictImportCancellationDoesNotModifyStore(t *testing.T) {
	svc, path, run := strictFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.ImportBundleStrict(ctx, path, run); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if countRows(t, svc.DB, "events", run) != 0 {
		t.Fatal("cancelled import changed store")
	}
}

func TestStrictImportKeepsEmptyFiles(t *testing.T) {
	svc, path, run := strictFixture(t)
	empty := alterBundle(t, path, func(bundle map[string]any) {
		bundle["snapshot_files"].([]any)[0].(map[string]any)["content_b64"] = ""
	})
	info, err := svc.ImportBundleStrict(context.Background(), empty, run)
	if err != nil || info.SnapshotFiles != 1 {
		t.Fatalf("empty snapshot file discarded: %+v %v", info, err)
	}
	var root string
	if err := svc.DB.QueryRow(`SELECT path FROM snapshots WHERE id='snapshot'`).Scan(&root); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(filepath.Join(root, "result.txt"))
	if err != nil || stat.Size() != 0 {
		t.Fatalf("empty file missing: %v %v", stat, err)
	}
}

func TestStrictImportDoesNotReuseTamperedArchive(t *testing.T) {
	svc, path, run := strictFixture(t)
	if _, err := svc.ImportBundleStrict(context.Background(), path, run); err != nil {
		t.Fatal(err)
	}
	var blob string
	if err := svc.DB.QueryRow(`SELECT path FROM provenance_objects`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportBundleStrict(context.Background(), path, run); !errors.Is(err, forensics.ErrBundleConflict) {
		t.Fatalf("corrupt archive accepted: %v", err)
	}
}

func TestStrictImportStorageFailureRollsBackProjection(t *testing.T) {
	svc, path, run := strictFixture(t)
	if _, err := svc.DB.Exec(`CREATE TRIGGER fail_import BEFORE INSERT ON provenance_objects BEGIN SELECT RAISE(ABORT,'disk fixture'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ImportBundleStrict(context.Background(), path, run)
	if err == nil || errors.Is(err, forensics.ErrBundleConflict) || !strings.Contains(err.Error(), "disk fixture") {
		t.Fatalf("storage error was hidden or relabeled: %v", err)
	}
	if countRows(t, svc.DB, "events", run) != 0 {
		t.Fatal("storage failure committed a partial projection")
	}
}

func TestStrictImportReusesLegacyContentPaths(t *testing.T) {
	svc, path, run := strictFixture(t)
	if _, err := svc.ImportBundle(path); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := svc.DB.QueryRow(`SELECT path FROM snapshots WHERE id='snapshot'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportBundleStrict(context.Background(), path, run); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := svc.DB.QueryRow(`SELECT path FROM snapshots WHERE id='snapshot'`).Scan(&after); err != nil || before != after {
		t.Fatalf("identical import rewrote existing path: %q %q %v", before, after, err)
	}
}

func TestStrictImportRealRecordedArtifact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell")
	}
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	const run = "recorded-import"
	workspace := filepath.Join(paths.Workspaces, "analysis")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "input.csv"), []byte("a,20\nb,22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := (record.Service{DB: db, Paths: paths, Options: record.Options{AllowShell: true}}).Run(record.Request{
		RunID: run, Workdir: workspace,
		Command: []string{"sh", "-c", `awk -F, '{sum+=$2} END {printf "total,%d\n",sum}' input.csv > result.csv`},
	})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("record: %+v %v", result, err)
	}
	if _, err := (provenance.ObjectStore{DB: db, Paths: paths}).MaterializeRun(run); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	dest := mustInit(t, filepath.Join(t.TempDir(), "receiver"))
	destDB := mustOpen(t, dest)
	defer destDB.Close()
	info, err := (forensics.Service{DB: destDB, Paths: dest}).ImportBundleStrict(context.Background(), bundle.Path, run)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(info.BundlePath, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	// Verification now depends only on receiver-owned files, not source paths.
	for _, path := range []string{paths.Snapshots, paths.Provenance, paths.Workspaces} {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
	}
	verified, err := provenance.Verify(destDB, run)
	if err != nil || verified.ErrorCount != 0 {
		t.Fatalf("received graph: %+v %v", verified, err)
	}
	if info.SnapshotFiles == 0 || info.ObjectBlobs == 0 || countRows(t, destDB, "events", run) == 0 {
		t.Fatalf("missing recorded evidence: %+v", info)
	}
	if len(result.ArtifactCapture.Files) != 1 || result.ArtifactCapture.Files[0].Path != "result.csv" {
		t.Fatalf("missing result artifact: %+v", result.ArtifactCapture)
	}
	page, err := provenance.ReadTextContentPage(destDB, run, result.ArtifactCapture.Files[0].ContentRef, 0, 4096)
	if err != nil || page.Content != "total,42\n" || page.HasMore {
		t.Fatalf("offline result content: %+v %v", page, err)
	}
}

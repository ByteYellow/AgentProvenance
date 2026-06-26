package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func openTestDB(t *testing.T) *Paths {
	t.Helper()
	paths, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return &paths
}

// TestConcurrentWritesDoNotError below is the live guarantee for write
// correctness under contention (WAL + busy_timeout). A stricter
// SetMaxOpenConns(1) serialization was evaluated and rejected - it deadlocks
// the codebase's nested-cursor read loops; see the note in Open.

func TestEnsureSchemaIsIdempotent(t *testing.T) {
	paths := openTestDB(t)
	db, err := Open(*paths)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	// Init already ran EnsureSchema once; running it again must not error.
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("second EnsureSchema: %v", err)
	}
	var version int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if version != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, SchemaVersion)
	}
}

func TestSignalsTableExists(t *testing.T) {
	paths := openTestDB(t)
	db, err := Open(*paths)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	var name string
	err = db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='signals'`).Scan(&name)
	if err != nil {
		t.Fatalf("signals table not created: %v", err)
	}
}

// TestConcurrentWritesDoNotError exercises the single-connection write
// serialization: many goroutines inserting concurrently must all succeed
// rather than hitting "database is locked".
func TestConcurrentWritesDoNotError(t *testing.T) {
	paths := openTestDB(t)
	db, err := Open(*paths)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	const writers = 16
	const perWriter = 25
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				id := fmt.Sprintf("lease-%d-%d", w, i)
				_, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
					VALUES (?, ?, '', '', 'open', datetime('now'), datetime('now'))`, id, id)
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&count); err != nil {
		t.Fatalf("count leases: %v", err)
	}
	if want := writers * perWriter; count != want {
		t.Fatalf("lease count = %d, want %d", count, want)
	}
}

func TestResolvePathsAbsolute(t *testing.T) {
	paths := ResolvePaths("relative/dir")
	if !filepath.IsAbs(paths.Root) {
		t.Fatalf("Root not absolute: %q", paths.Root)
	}
	if filepath.Base(paths.DB) != "agentprov.db" {
		t.Fatalf("DB path = %q, want .../agentprov.db", paths.DB)
	}
}

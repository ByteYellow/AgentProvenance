package store

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSchemaMigrationFailureRollsBackAllDDL(t *testing.T) {
	db, err := Open(ResolvePaths(filepath.Join(t.TempDir(), "store")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, sql := range []string{
		`CREATE TABLE schema_versions(version INTEGER PRIMARY KEY,description TEXT NOT NULL,applied_at TEXT NOT NULL)`,
		`INSERT INTO schema_versions VALUES(1,'fixture','now')`,
		`CREATE TRIGGER reject_schema BEFORE INSERT ON schema_versions WHEN NEW.version>1 BEGIN SELECT RAISE(ABORT,'fixture schema commit rejected'); END`,
	} {
		if _, err := db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	if err := EnsureSchema(db); err == nil || !strings.Contains(err.Error(), "fixture schema commit rejected") {
		t.Fatalf("migration failure: %v", err)
	}
	var count, version int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name!='schema_versions'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial migration tables: count=%d err=%v", count, err)
	}
	if err := db.QueryRow(`SELECT max(version) FROM schema_versions`).Scan(&version); err != nil || version != 1 {
		t.Fatalf("failed migration advanced version: %d %v", version, err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_schema`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT max(version) FROM schema_versions`).Scan(&version); err != nil || version != SchemaVersion {
		t.Fatalf("recovery did not complete schema: %d %v", version, err)
	}
}

func TestConcurrentSchemaInitialization(t *testing.T) {
	paths := ResolvePaths(filepath.Join(t.TempDir(), "store"))
	var workers sync.WaitGroup
	start := make(chan struct{})
	errors := make(chan error, 4)
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			db, err := Open(paths)
			if err != nil {
				errors <- err
				return
			}
			defer db.Close()
			<-start
			errors <- EnsureSchema(db)
		}()
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

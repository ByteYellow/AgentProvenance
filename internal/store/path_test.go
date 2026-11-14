package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreReservedPathCharacters(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"ordinary", "store#a", "store#b", "store?mode=ro", "store%2fencoded", "store space"} {
		t.Run(name, func(t *testing.T) {
			paths, err := Init(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			db, err := Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if info, err := os.Stat(paths.DB); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("database was not created at requested path: %v", err)
			}
			var count int
			if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("store shared another path's rows: %d %v", count, err)
			}
			if _, err := db.Exec(`INSERT INTO events(id,event_type,source,run_id,payload,created_at) VALUES('path-test','test','test','r','{}','2026-11-14T00:00:00Z')`); err != nil {
				t.Fatal(err)
			}
			var mode string
			if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
				t.Fatalf("lost DSN pragmas: %s %v", mode, err)
			}
		})
	}
}

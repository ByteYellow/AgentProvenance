package forensics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestBoundedExportRejectsTotalSizeAndCancellation(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES('e','r','test','note',?,'2026-11-14T00:00:00Z')`, strings.Repeat("a", 8192)); err != nil {
		t.Fatal(err)
	}
	s := Service{DB: db, Paths: paths}
	if _, err := s.ExportBundleBounded(context.Background(), "r", 4096); err == nil {
		t.Fatal("total size limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ExportBundleBounded(ctx, "r", MaxStrictBundleBytes); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled export: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM forensics_bundles").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed export saved a ready bundle: %d %v", count, err)
	}
	if _, err := s.ExportBundleBounded(context.Background(), "r", 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExportBundle("r"); err != nil {
		t.Fatalf("legacy export changed: %v", err)
	}
}

func TestBoundedExportAccumulatesObjectBodies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "object")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 8192)), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []map[string]any{{"hash": "a", "path": path}, {"hash": "b", "path": path}}
	if _, _, err := embedObjectBlobsBounded(rows, &exportBudget{ctx: context.Background(), limit: 16000}); err == nil {
		t.Fatal("per-object reads bypassed total export budget")
	}
}

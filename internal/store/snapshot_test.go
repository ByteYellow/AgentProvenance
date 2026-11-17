package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFreezeDatabaseCommittedVersion(t *testing.T) {
	paths := ResolvePaths(filepath.Join(t.TempDir(), "source #?%"))
	db, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE sample (value TEXT); INSERT INTO sample VALUES ('committed')"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE sample SET value='pending'"); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "frozen.db")
	if err := FreezeDatabase(context.Background(), db, destination); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	frozen, err := sql.Open("sqlite", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer frozen.Close()
	var value string
	if err := frozen.QueryRow("SELECT value FROM sample").Scan(&value); err != nil || value != "committed" {
		t.Fatalf("snapshot mixed committed versions: %q %v", value, err)
	}
	if err := db.QueryRow("SELECT value FROM sample").Scan(&value); err != nil || value != "pending" {
		t.Fatalf("snapshot changed source: %q %v", value, err)
	}
	if err := FreezeDatabase(context.Background(), db, destination); err == nil {
		t.Fatal("overwrote an existing snapshot")
	}
	if err := frozen.QueryRow("SELECT value FROM sample").Scan(&value); err != nil || value != "committed" {
		t.Fatalf("failed export changed snapshot: %q %v", value, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := filepath.Join(t.TempDir(), "cancelled.db")
	if err := FreezeDatabase(ctx, db, cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled snapshot: %v", err)
	}
	if _, err := os.Stat(cancelled); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled snapshot published a file: %v", err)
	}
}

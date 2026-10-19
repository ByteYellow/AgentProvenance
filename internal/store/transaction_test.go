package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestWithTxDiscardsFailedCommit(t *testing.T) {
	paths, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		`CREATE TABLE parent (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE child (id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := WithTx(context.Background(), db, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO child VALUES (1)`)
		return err
	}); err == nil {
		t.Fatal("expected deferred constraint failure at commit")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM child`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed transaction escaped into pool: %d %v", n, err)
	}
	if err := WithTx(context.Background(), db, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO parent VALUES (1)`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO child VALUES (1)`)
		return err
	}); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestWithTxRollsBackCallbackFailure(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panics], func(t *testing.T) {
			paths, err := Init(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			db, err := Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			failure := errors.New("injected failure")
			func() {
				if panics {
					defer func() {
						if got := recover(); got != failure {
							t.Fatalf("unexpected panic: %v", got)
						}
					}()
				}
				err := WithTx(context.Background(), db, func(tx *sql.Tx) error {
					if _, err := tx.Exec(`INSERT INTO events (id,source,event_type,payload,created_at) VALUES ('test','test','test','{}','now')`); err != nil {
						t.Fatal(err)
					}
					if panics {
						panic(failure)
					}
					return failure
				})
				if !errors.Is(err, failure) {
					t.Fatalf("callback error lost: %v", err)
				}
			}()
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("rollback: %d %v", n, err)
			}
		})
	}
}

package store

import (
	"context"
	"database/sql"
	"sync"
	"testing"
)

func TestCurrentSchemaReadsWhileWriterHoldsLock(t *testing.T) {
	paths := openTestDB(t)
	writer, err := Open(*paths)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	tx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO leases(id,run_id,task_path,task_yaml,status,created_at,updated_at) VALUES('lock','lock','','','open','now','now')`); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(*paths)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := EnsureSchema(reader); err != nil {
		t.Fatalf("read-only startup contended with collector: %v", err)
	}
	var n int
	if err := reader.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
}

func TestRetryBusyWritesOnceAfterAnotherWriterCommits(t *testing.T) {
	paths := openTestDB(t)
	writer, err := Open(*paths)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	tx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO leases(id,run_id,task_path,task_yaml,status,created_at,updated_at) VALUES('lock','lock','','','open','now','now')`); err != nil {
		t.Fatal(err)
	}
	other, err := sql.Open("sqlite", "file:"+paths.DB+"?_pragma=busy_timeout(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	contended, committed := make(chan struct{}), make(chan error, 1)
	go func() { <-contended; committed <- tx.Commit() }()
	var once sync.Once
	attempts := 0
	err = RetryBusy(context.Background(), func() error {
		attempts++
		_, err := other.Exec(`UPDATE leases SET status=status||'-updated' WHERE id='lock'`)
		if IsBusy(err) {
			once.Do(func() { close(contended) })
		}
		return err
	})
	once.Do(func() { close(contended) })
	if commitErr := <-committed; commitErr != nil {
		t.Fatal(commitErr)
	}
	if err != nil || attempts < 2 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
	var status string
	if err := other.QueryRow(`SELECT status FROM leases WHERE id='lock'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "open-updated" {
		t.Fatalf("write replayed: %s", status)
	}
}

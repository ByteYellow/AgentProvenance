package agentcontext

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestContextWritesWaitForCollector(t *testing.T) {
	for _, operation := range []string{"new-policy", "existing-policy", "ensure-policy", "diagnostic"} {
		t.Run(operation, func(t *testing.T) {
			s := testService(t)
			s.DB.SetMaxOpenConns(1)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if operation == "existing-policy" {
				if _, err := s.EnsureCapturePolicy(ctx, "run"); err != nil {
					t.Fatal(err)
				}
			}
			writer, err := store.Open(s.Paths)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			tx, err := writer.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, `INSERT INTO events(id,source,event_type,payload,created_at) VALUES('collector','sensor','execve','{}','now')`); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if operation == "ensure-policy" {
					_, err := s.EnsureCapturePolicy(ctx, "run")
					done <- err
					return
				}
				body := "saved tool output"
				records := []Record{{Key: "result", Kind: "tool_result", Body: &body}}
				report := Coverage{Status: OK}
				if operation == "diagnostic" {
					records, report = nil, Coverage{Status: Failed, Issues: []Issue{{Code: "context_capture_failed"}}}
				}
				result, err := s.Save(ctx, "run", testSource(), records, report)
				if err == nil && result.Stored != len(records) {
					err = fmt.Errorf("stored %d records, want %d", result.Stored, len(records))
				}
				done <- err
			}()
			select {
			case err := <-done:
				t.Fatalf("context import returned while collector still held writer: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("context write after collector commit: %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			for _, query := range []string{
				`SELECT COUNT(*) FROM provenance_objects WHERE object_type='context_capture_policy' AND run_id='run'`,
				`SELECT COUNT(*) FROM events WHERE id='collector'`,
			} {
				var count int
				if err := s.DB.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 1 {
					t.Fatalf("committed row count=%d err=%v", count, err)
				}
			}
			if operation != "ensure-policy" {
				var count int
				if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_context_reports WHERE run_id='run'`).Scan(&count); err != nil || count != 1 {
					t.Fatalf("coverage count=%d err=%v", count, err)
				}
			}
		})
	}
}

func TestContextFailedCommitDoesNotPublishOrPoisonConnection(t *testing.T) {
	s := testService(t)
	s.DB.SetMaxOpenConns(1)
	for _, query := range []string{
		`CREATE TABLE context_parent(id INTEGER PRIMARY KEY)`,
		`CREATE TABLE context_child(id INTEGER REFERENCES context_parent(id) DEFERRABLE INITIALLY DEFERRED)`,
		`CREATE TRIGGER context_commit_failure AFTER INSERT ON agent_context_reports BEGIN INSERT INTO context_child VALUES(1); END`,
	} {
		if _, err := s.DB.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	body := "atomic output"
	records := []Record{{Key: "one", Kind: "message", Body: &body}}
	result, err := s.Save(context.Background(), "run", testSource(), records, Coverage{Status: OK})
	if err == nil || result.Stored != 0 || result.Coverage.ObjectHash != "" {
		t.Fatalf("failed commit published result: %+v %v", result, err)
	}
	for _, table := range []string{"agent_context_entries", "agent_context_reports", "provenance_objects", "context_child"} {
		var count int
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
	if _, err := s.DB.Exec(`DROP TRIGGER context_commit_failure`); err != nil {
		t.Fatal(err)
	}
	result, err = s.Save(context.Background(), "run", testSource(), records, Coverage{Status: OK})
	if err != nil || result.Stored != 1 {
		t.Fatalf("retry failed: %+v %v", result, err)
	}
}

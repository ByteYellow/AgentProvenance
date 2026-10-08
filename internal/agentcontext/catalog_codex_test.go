package agentcontext

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCatalog(t *testing.T, path string, rows [][2]string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE threads (id TEXT, rollout_path TEXT, updated_at_ms INTEGER)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, row := range rows {
		if _, err := tx.Exec(`INSERT INTO threads VALUES (?, ?, ?)`, row[0], row[1], time.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func hasDiscoveryIssue(inv Inventory, code string) bool {
	for _, issue := range inv.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestCodexCatalogAddsExternalPathsWithoutChangingSource(t *testing.T) {
	home, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	local := filepath.Join(home, "sessions", "rollout-local.jsonl")
	external := filepath.Join(t.TempDir(), "acquired-session.jsonl")
	writeSource(t, local, codexHeader("one", "", cwd, now))
	writeSource(t, external, codexHeader("two", "", cwd, now.Add(-24*time.Hour)))
	catalog := filepath.Join(home, "state_9.sqlite")
	writeCatalog(t, catalog, [][2]string{{"one", "sessions/rollout-local.jsonl"}, {"two", external}})
	writeCatalog(t, filepath.Join(home, "state_10.sqlite"), [][2]string{{"one", local}, {"two", external}})
	before, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	opts := DiscoverOptions{Harness: "codex", Root: filepath.Join(home, "sessions"), CatalogRoot: home, Workdir: cwd, Snapshot: true}
	inv := discoverTest(t, opts)
	if !inv.Complete || len(inv.Candidates) != 2 || len(inv.Issues) != 0 || inv.CatalogRoot != home {
		t.Fatalf("catalog discovery: %+v", inv)
	}
	for _, candidate := range inv.Candidates {
		if !candidate.Cursor.Valid {
			t.Fatalf("catalog path not checkpointed: %+v", candidate)
		}
		if candidate.SessionID == "two" && candidate.CreatedAt != now.Add(-24*time.Hour).Format(time.RFC3339Nano) {
			t.Fatal("catalog freshness substituted for source time")
		}
	}
	after, err := os.ReadFile(catalog)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("catalog modified: %v", err)
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Stat(catalog + suffix); !os.IsNotExist(err) {
			t.Fatalf("unexpected catalog sidecar %s: %v", suffix, err)
		}
	}
	// Explicit acquisition never consults an unrelated ambient CODEX_HOME.
	t.Setenv("CODEX_HOME", home)
	isolated := discoverTest(t, DiscoverOptions{Harness: "codex", Root: t.TempDir()})
	if !isolated.Complete || len(isolated.Candidates) != 0 {
		t.Fatalf("ambient sessions included: %+v", isolated)
	}
}

func TestCodexCatalogConcurrencyResumeAndIdentityConflicts(t *testing.T) {
	home, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "codex", Root: home, Workdir: cwd, Snapshot: true}
	before := discoverTest(t, opts)
	local, external := filepath.Join(home, "rollout-one.jsonl"), filepath.Join(t.TempDir(), "other.jsonl")
	writeSource(t, local, codexHeader("one", "", cwd, now))
	writeSource(t, external, codexHeader("two", "", cwd, now))
	writeCatalog(t, filepath.Join(home, "state_1.sqlite"), [][2]string{{"two", external}})
	after := discoverTest(t, opts)
	window := SelectOptions{Workdir: cwd, StartedAt: now.Add(-time.Second), EndedAt: now.Add(time.Second)}
	selected := SelectSources(context.Background(), before, after, window)
	if selected.Status != Ambiguous || len(selected.Sources) != 0 {
		t.Fatalf("catalog candidate ignored in uniqueness check: %+v", selected)
	}
	writeSource(t, external, codexHeader("two", "", cwd, now)+`{"type":"event_msg","payload":{"type":"user_message","message":"continued"}}`+"\n")
	window.SessionID = "two"
	selected = SelectSources(context.Background(), after, discoverTest(t, opts), window)
	if selected.Status != OK || len(selected.Sources) != 1 || selected.Sources[0].AfterLine != 1 || selected.Sources[0].ResumeCursor == nil {
		t.Fatalf("external resume prefix lost: %+v", selected)
	}
	writeCatalog(t, filepath.Join(home, "state_2.sqlite"), [][2]string{{"wrong-identity", external}})
	conflicted := discoverTest(t, opts)
	if conflicted.Complete || !hasDiscoveryIssue(conflicted, "catalog_session_identity_conflict") {
		t.Fatalf("catalog identity accepted as authoritative: %+v", conflicted)
	}
	selected = SelectSources(context.Background(), before, conflicted, window)
	if selected.Status != Ambiguous || len(selected.Sources) != 0 {
		t.Fatalf("conflicted identity bound: %+v", selected)
	}
}

func TestCodexCatalogFailureDoesNotDiscardReadableFiles(t *testing.T) {
	for _, mode := range []string{"corrupt", "schema", "view", "missing", "symlink", "invalid-row"} {
		t.Run(mode, func(t *testing.T) {
			home, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
			opts := DiscoverOptions{Harness: "codex", Root: home, Workdir: cwd}
			before := discoverTest(t, opts)
			path := filepath.Join(home, "rollout-readable.jsonl")
			writeSource(t, path, codexHeader("readable", "", cwd, now))
			catalog := filepath.Join(home, "state_1.sqlite")
			switch mode {
			case "corrupt":
				writeSource(t, catalog, "not a database")
			case "schema", "view":
				db, err := sql.Open("sqlite", catalog)
				if err != nil {
					t.Fatal(err)
				}
				statement := `CREATE TABLE unrelated (value TEXT)`
				if mode == "view" {
					statement = `CREATE VIEW threads AS SELECT 'id' AS id, '/missing.jsonl' AS rollout_path`
				}
				_, err = db.Exec(statement)
				db.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "missing":
				writeCatalog(t, catalog, [][2]string{{"gone", "/missing-session.jsonl"}})
			case "symlink":
				link := filepath.Join(home, "linked.jsonl")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				writeCatalog(t, catalog, [][2]string{{"readable", link}})
			case "invalid-row":
				writeCatalog(t, catalog, [][2]string{{"private-do-not-log", strings.Repeat("x", 5000)}})
			}
			after := discoverTest(t, opts)
			if after.Complete || len(after.Candidates) != 1 || len(after.Issues) == 0 {
				t.Fatalf("failure/usable source lost: %+v", after)
			}
			if strings.Contains(fmt.Sprint(after.Issues), "private-do-not-log") {
				t.Fatal("catalog data leaked into diagnostics")
			}
			window := SelectOptions{Workdir: cwd, StartedAt: now.Add(-time.Second), EndedAt: now.Add(time.Second)}
			if s := SelectSources(context.Background(), before, after, window); s.Status != Ambiguous || len(s.Sources) != 0 {
				t.Fatalf("incomplete catalog treated as unique: %+v", s)
			}
			window.Path = path
			if s := SelectSources(context.Background(), before, after, window); s.Status != Partial || len(s.Sources) != 1 {
				t.Fatalf("explicit readable source blocked: %+v", s)
			}
		})
	}
}

func TestCodexCatalogRowBudgetAndCancellation(t *testing.T) {
	home, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	path := filepath.Join(home, "rollout-one.jsonl")
	writeSource(t, path, codexHeader("one", "", cwd, now))
	rows := make([][2]string, MaxDiscoveryFiles+2)
	for i := range rows {
		rows[i] = [2]string{"one", path}
	}
	writeCatalog(t, filepath.Join(home, "state_1.sqlite"), rows)
	opts := DiscoverOptions{Harness: "codex", Root: home}
	inv := discoverTest(t, opts)
	if inv.Complete || !hasDiscoveryIssue(inv, "catalog_row_limit") || len(inv.Candidates) != 1 {
		t.Fatalf("unbounded catalog or duplicate source: %+v", inv)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, opts); err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestCodexCatalogReadsCommittedWALDuringWriterTransaction(t *testing.T) {
	home, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
	first, second := filepath.Join(t.TempDir(), "first.jsonl"), filepath.Join(t.TempDir(), "second.jsonl")
	writeSource(t, first, codexHeader("first", "", cwd, now))
	writeSource(t, second, codexHeader("second", "", cwd, now))
	path := filepath.Join(home, "state_1.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA wal_autocheckpoint=0`, `CREATE TABLE threads (id TEXT, rollout_path TEXT)`} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO threads VALUES (?, ?)`, "first", first); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO threads VALUES (?, ?)`, "second", second); err != nil {
		t.Fatal(err)
	}
	walBefore, err := os.ReadFile(path + "-wal")
	if err != nil || len(walBefore) == 0 {
		t.Fatalf("no live catalog WAL: %v", err)
	}
	inv := discoverTest(t, DiscoverOptions{Harness: "codex", Root: home, Workdir: cwd, Snapshot: true})
	if !inv.Complete || len(inv.Candidates) != 1 || inv.Candidates[0].SessionID != "first" || !inv.Candidates[0].Cursor.Valid {
		t.Fatalf("uncommitted or stale catalog state: %+v", inv)
	}
	walAfter, err := os.ReadFile(path + "-wal")
	if err != nil || !bytes.Equal(walBefore, walAfter) {
		t.Fatalf("catalog discovery modified WAL: %v", err)
	}
}

func TestCodexLockedCatalogMarksDiscoveryIncomplete(t *testing.T) {
	home, now := t.TempDir(), time.Now().UTC()
	opts := DiscoverOptions{Harness: "codex", Root: home, Workdir: home}
	before := discoverTest(t, opts)
	path := filepath.Join(home, "rollout-readable.jsonl")
	writeSource(t, path, codexHeader("readable", "", home, now))
	catalog := filepath.Join(home, "state_1.sqlite")
	writeCatalog(t, catalog, [][2]string{{"readable", path}})
	db, err := sql.Open("sqlite", catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ROLLBACK`)
	after := discoverTest(t, opts)
	if after.Complete || !hasDiscoveryIssue(after, "catalog_unreadable") || len(after.Candidates) != 1 {
		t.Fatalf("locked catalog treated as empty: %+v", after)
	}
	window := SelectOptions{Workdir: home, StartedAt: now.Add(-time.Second), EndedAt: now.Add(time.Second)}
	if selection := SelectSources(context.Background(), before, after, window); selection.Status != Ambiguous || len(selection.Sources) != 0 {
		t.Fatalf("incomplete catalog allowed automatic binding: %+v", selection)
	}
}

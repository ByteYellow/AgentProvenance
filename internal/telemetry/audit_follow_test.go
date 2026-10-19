//go:build linux || darwin

package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
	"golang.org/x/sys/unix"
)

func auditFollowFixture(t *testing.T, input string) (*sql.DB, store.Paths, AuditFollowOptions) {
	t.Helper()
	db, paths := nativeTestStore(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	return db, paths, AuditFollowOptions{AuditIngestOptions: AuditIngestOptions{RunID: "run-follow", Path: path, Source: auditTestSource}, Once: true}
}

func followAuditOnce(t *testing.T, db *sql.DB, paths store.Paths, opts AuditFollowOptions) AuditFollowStatus {
	t.Helper()
	r, err := FollowAuditFile(context.Background(), db, paths, opts, nil)
	if err != nil {
		t.Fatalf("follow: %+v %v", r, err)
	}
	return r
}

func appendAuditFixture(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteString(text)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append: %v %v", writeErr, closeErr)
	}
}

func auditFollowCount(t *testing.T, db *sql.DB, table, predicate string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE ` + predicate).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAuditFollowPartialLineResumeAndDedup(t *testing.T) {
	db, paths, opts := auditFollowFixture(t, auditTestSeccomp)
	r := followAuditOnce(t, db, paths, opts)
	if r.Reader.Read != 0 || r.Reader.CommittedOffset != 0 || r.Reader.PendingBytes != int64(len(auditTestSeccomp)) || r.Reader.Reason != "pending_source_bytes" {
		t.Fatalf("partial line acknowledged: %+v", r)
	}
	appendAuditFixture(t, opts.Path, "\n")
	r = followAuditOnce(t, db, paths, opts)
	if r.Reader.Read != 1 || r.Reader.Ingested != 1 || r.Reader.PendingBytes != 0 || r.Reader.UpstreamLoss != "unknown" {
		t.Fatalf("completed line: %+v", r)
	}
	appendAuditFixture(t, opts.Path, auditTestSeccomp+"\n")
	r = followAuditOnce(t, db, paths, opts)
	if r.Reader.Read != 2 || r.Reader.Ingested != 1 || r.Reader.Duplicates != 1 {
		t.Fatalf("duplicate source delivery: %+v", r)
	}
	before := r.Reader
	r = followAuditOnce(t, db, paths, opts)
	if r.Reader.Read != before.Read || r.Reader.Batches != before.Batches || r.Reader.CommittedOffset != before.CommittedOffset {
		t.Fatalf("repeated empty read reingested source: %+v", r)
	}
	if n := auditFollowCount(t, db, "events", "event_type='access_control'"); n != 1 {
		t.Fatalf("audit count=%d", n)
	}
	events, err := ListEvents(db, opts.RunID, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := ValidateStoredPayload(e.EventType, e.Payload); err != nil || e.PID != 0 || e.SessionID != "" || e.ToolCallID != "" {
			t.Fatalf("invalid or guessed scope: %+v %v", e, err)
		}
	}
}

func TestAuditFollowCheckpointAndEvidenceAtomic(t *testing.T) {
	for _, target := range []string{"telemetry_batches", "telemetry_audit_checkpoints"} {
		t.Run(target, func(t *testing.T) {
			db, paths, opts := auditFollowFixture(t, "")
			before := followAuditOnce(t, db, paths, opts)
			appendAuditFixture(t, opts.Path, auditTestSeccomp+"\n")
			trigger := `CREATE TRIGGER fail_follow BEFORE INSERT ON telemetry_batches BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END`
			if target == "telemetry_audit_checkpoints" {
				trigger = `CREATE TRIGGER fail_follow BEFORE UPDATE ON telemetry_audit_checkpoints WHEN json_extract(NEW.checkpoint_json,'$.observation.committed_offset')>0 BEGIN SELECT RAISE(ABORT,'fixture checkpoint failure'); END`
			}
			if _, err := db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			r, err := FollowAuditFile(context.Background(), db, paths, opts, nil)
			if err == nil || r.Reader.CommittedOffset != before.Reader.CommittedOffset || r.Reader.Ingested != 0 || r.Reader.Reason != "storage_error" {
				t.Fatalf("failed transaction advanced: %+v %v", r, err)
			}
			if n := auditFollowCount(t, db, "events", "event_type='access_control'"); n != 0 {
				t.Fatalf("events survived rollback: %d", n)
			}
			if n := auditFollowCount(t, db, "telemetry_batches", "1=1"); n != 0 {
				t.Fatalf("receipt survived rollback: %d", n)
			}
			if _, err := db.Exec(`DROP TRIGGER fail_follow`); err != nil {
				t.Fatal(err)
			}
			r = followAuditOnce(t, db, paths, opts)
			if r.Reader.Ingested != 1 || r.Reader.Read != 1 {
				t.Fatalf("retry failed: %+v", r)
			}
		})
	}
}

func TestAuditFollowSourceContinuityFailures(t *testing.T) {
	for _, mode := range []string{"source_replaced", "source_truncated", "source_rewritten", "source_missing"} {
		t.Run(mode, func(t *testing.T) {
			db, paths, opts := auditFollowFixture(t, auditTestSeccomp+"\n")
			before := followAuditOnce(t, db, paths, opts)
			var err error
			switch mode {
			case "source_replaced":
				if err = os.Rename(opts.Path, opts.Path+".1"); err == nil {
					err = os.WriteFile(opts.Path, []byte(auditTestSeccomp+"\n"), 0600)
				}
			case "source_truncated":
				err = os.Truncate(opts.Path, 0)
			case "source_rewritten":
				err = os.WriteFile(opts.Path, []byte(strings.Replace(auditTestSeccomp, "pid=42", "pid=43", 1)+"\n"), 0600)
			case "source_missing":
				err = os.Remove(opts.Path)
			}
			if err != nil {
				t.Fatal(err)
			}
			r, err := FollowAuditFile(context.Background(), db, paths, opts, nil)
			if err == nil || r.Reader.Reason != mode || r.Reader.Status != "failed" || r.Reader.CommittedOffset != before.Reader.CommittedOffset {
				t.Fatalf("continuity failure: %+v %v", r, err)
			}
			var reason string
			if err := db.QueryRow(`SELECT json_extract(checkpoint_json,'$.observation.reason') FROM telemetry_audit_checkpoints WHERE id=?`, r.Reader.ReaderID).Scan(&reason); err != nil || reason != mode {
				t.Fatalf("failure diagnostic missing: %s %v", reason, err)
			}
		})
	}
}

func TestAuditFollowBoundedBatchesRetentionAndMalformedRows(t *testing.T) {
	for _, keep := range []bool{false, true} {
		db, paths, opts := auditFollowFixture(t, "")
		opts.Source, opts.RetainRaw = AuditSource{}, keep
		secret := "sk-" + strings.Repeat("s", 32)
		input := strings.Repeat(auditTestSeccomp+` info="`+secret+`"`+"\n", 270) + "type=SECCOMP msg=audit(bad)\nignored\n"
		appendAuditFixture(t, opts.Path, input)
		r := followAuditOnce(t, db, paths, opts)
		if r.Reader.Read != 272 || r.Reader.Ingested != 270 || r.Reader.Failed != 1 || r.Reader.Skipped != 1 || r.Reader.IdentityIncomplete != 270 || r.Reader.Batches != 3 {
			t.Fatalf("counts: %+v", r)
		}
		repeated := followAuditOnce(t, db, paths, opts)
		if repeated.Reader.Ingested != 270 || repeated.Reader.Read != 272 {
			t.Fatalf("unidentified records replayed: %+v", repeated)
		}
		events, err := ListEvents(db, opts.RunID, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if strings.Contains(e.Payload, secret) {
				t.Fatal("secret persisted")
			}
			if e.EventType == "access_control" {
				record := storedAuditTest(t, e.Payload)
				if (record.RawRecord.Text != "") != keep {
					t.Fatalf("retention changed: %+v", record)
				}
			}
		}
		var maxRows int
		if err := db.QueryRow(`SELECT MAX(read_count) FROM telemetry_batches`).Scan(&maxRows); err != nil || maxRows > 128 {
			t.Fatalf("unbounded batch: %d %v", maxRows, err)
		}
	}
}

func TestAuditFollowJournalMechanismAndSourceSettings(t *testing.T) {
	journal, _ := json.Marshal(map[string]string{"MESSAGE": auditTestSeccomp, "_MACHINE_ID": auditTestSource.HostID, "_BOOT_ID": auditTestSource.BootID, "__CURSOR": "fixture-cursor"})
	input := string(journal) + "\n" + `type=AVC msg=audit(1792342593.757:131): apparmor="DENIED" operation="open" pid=42 name="/tmp/fixture"` + "\n"
	db, paths, opts := auditFollowFixture(t, input)
	opts.Mechanism = "seccomp"
	r := followAuditOnce(t, db, paths, opts)
	if r.Reader.Ingested != 1 || r.Reader.Skipped != 1 || r.Reader.IdentityIncomplete != 0 {
		t.Fatalf("journal/filter: %+v", r)
	}
	opts.ReaderID, opts.Mechanism = r.Reader.ReaderID, "all"
	if _, err := FollowAuditFile(context.Background(), db, paths, opts, nil); err == nil || !strings.Contains(err.Error(), "settings differ") {
		t.Fatalf("checkpoint options changed: %v", err)
	}
	if n := auditFollowCount(t, db, "events", "event_type='access_control'"); n != 1 {
		t.Fatalf("option mismatch changed evidence: %d", n)
	}
}

func TestAuditFollowContinuousAppendCancellationAndLock(t *testing.T) {
	db, paths, opts := auditFollowFixture(t, "")
	opts.Once, opts.PollInterval = false, 50*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	appended, lockChecked := false, false
	r, err := FollowAuditFile(ctx, db, paths, opts, func(s AuditFollowStatus) error {
		if !lockChecked {
			lockChecked = true
			if _, err := FollowAuditFile(ctx, db, paths, opts, nil); err == nil {
				return fmt.Errorf("second reader acquired the same checkpoint")
			}
		}
		if s.Reader.Status == "waiting" && !appended {
			appended = true
			appendAuditFixture(t, opts.Path, auditTestSeccomp+"\n")
		}
		if s.Reader.Ingested == 1 {
			cancel()
		}
		return nil
	})
	if err != nil || !appended || r.Reader.Ingested != 1 || r.Reader.Status != "stopped" || r.Reader.Reason != "requested_stop" {
		t.Fatalf("continuous follow: %+v %v", r, err)
	}
	opts.Once = true
	if after := followAuditOnce(t, db, paths, opts); after.Reader.Ingested != 1 {
		t.Fatalf("stop lost checkpoint: %+v", after)
	}
}

func TestAuditFollowRejectsOversizeAndNonRegularSources(t *testing.T) {
	db, paths, opts := auditFollowFixture(t, strings.Repeat("x", MaxAuditLineBytes+1)+"\n")
	r, err := FollowAuditFile(context.Background(), db, paths, opts, nil)
	if err == nil || r.Reader.Read != 0 || r.Reader.CommittedOffset != 0 || r.Reader.Status != "failed" {
		t.Fatalf("oversize acknowledged: %+v %v", r, err)
	}
	opts.Path = filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(opts.Path, 0600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	r, err = FollowAuditFile(context.Background(), db, paths, opts, nil)
	if err == nil || r.Reader.Reason != "source_unavailable" || time.Since(started) > time.Second {
		t.Fatalf("non-regular source blocked: %+v %v", r, err)
	}
}

func TestAuditFollowCrashRecovery(t *testing.T) {
	if dir := os.Getenv("AGENTPROV_AUDIT_CRASH_DIR"); dir != "" {
		paths, err := store.Init(dir)
		if err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(paths)
		if err != nil {
			t.Fatal(err)
		}
		opts := AuditFollowOptions{AuditIngestOptions: AuditIngestOptions{RunID: "run-crash", Path: filepath.Join(dir, "audit.log")}, Once: true}
		_, err = FollowAuditFile(context.Background(), db, paths, opts, func(s AuditFollowStatus) error {
			if s.Reader.Ingested == 128 {
				os.Exit(23)
			}
			return nil
		})
		t.Fatalf("fixture failed to exit after first committed batch: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(strings.Repeat(auditTestSeccomp+"\n", 257)), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuditFollowCrashRecovery$")
	cmd.Env = append(os.Environ(), "AGENTPROV_AUDIT_CRASH_DIR="+dir)
	output, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 23 {
		t.Fatalf("crash fixture: %v %s", err, output)
	}
	paths, err := store.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if count := auditFollowCount(t, db, "events", "event_type='access_control'"); count != 128 {
		t.Fatalf("crash did not preserve first transaction: %d", count)
	}
	r := followAuditOnce(t, db, paths, AuditFollowOptions{AuditIngestOptions: AuditIngestOptions{RunID: "run-crash", Path: path}, Once: true})
	if r.Reader.Ingested != 257 || r.Reader.Read != 257 || r.Reader.Batches != 3 || r.Reader.IdentityIncomplete != 257 {
		t.Fatalf("crash recovery duplicated or lost unidentified rows: %+v", r)
	}
}

package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

func TestAuditIngestDeduplicatesWithoutGuessingSession(t *testing.T) {
	db, _ := nativeTestStore(t)
	if _, err := correlation.RecordBinding(db, correlation.Binding{RunID: "run", SessionID: "tempting-session", ToolCallID: "tempting-tool", PID: 42, StartedAt: "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	journal, _ := json.Marshal(map[string]string{"MESSAGE": strings.Replace(auditTestSeccomp, "type=SECCOMP msg=", "audit: type=1326 ", 1), "_MACHINE_ID": auditTestSource.HostID, "_BOOT_ID": auditTestSource.BootID})
	input := auditTestSeccomp + "\n" + string(journal) + "\n"
	opts := AuditIngestOptions{RunID: "run", Path: "fixture", Source: auditTestSource, RetainRaw: true}
	r, err := IngestAuditReader(context.Background(), db, opts, strings.NewReader(input))
	if err != nil || r.Read != 2 || r.Ingested != 1 || r.Duplicates != 1 || r.Status != "completed" {
		t.Fatalf("duplicate result: %+v %v", r, err)
	}
	sum := sha256.Sum256([]byte(input))
	if r.FileSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("input hash changed")
	}
	events, err := ListEvents(db, "run", "")
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	e := events[0]
	if e.Source != "seccomp_audit" || e.EventType != "access_control" || e.SessionID != "" || e.ToolCallID != "" || e.PID != 0 || e.CorrelationConfidence != 0 {
		t.Fatalf("PID alone assigned a Session: %+v", e)
	}
	record := storedAuditTest(t, e.Payload)
	if record.AuditPID == nil || *record.AuditPID != 42 || record.Decision != "LOG" || record.RawRecord.Text == "" {
		t.Fatalf("audit payload lost: %+v", record)
	}
	if err := ValidateStoredPayload(e.EventType, e.Payload); err != nil {
		t.Fatal(err)
	}
	if r, err := IngestAuditReader(context.Background(), db, opts, strings.NewReader(input)); err != nil || r.Ingested != 0 || r.Duplicates != 2 {
		t.Fatalf("retry duplicated evidence: %+v %v", r, err)
	}
	var count int
	if err := db.QueryRow(`SELECT SUM(event_count) FROM telemetry_event_windows WHERE window_seconds=10`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate inflated window: count=%d err=%v", count, err)
	}
}

func TestAuditIngestCaptureRetentionAndSecretRedaction(t *testing.T) {
	secret := "sk-" + strings.Repeat("a", 32)
	input := auditTestSeccomp + ` info="` + secret + `"`
	for _, keepRaw := range []bool{false, true} {
		db, _ := nativeTestStore(t)
		r, err := IngestAuditReader(context.Background(), db, AuditIngestOptions{RunID: "run", Source: auditTestSource, RetainRaw: keepRaw}, strings.NewReader(input))
		if err != nil || r.Ingested != 1 {
			t.Fatalf("result=%+v err=%v", r, err)
		}
		events, err := ListEvents(db, "run", "")
		if err != nil || len(events) != 1 {
			t.Fatal(err)
		}
		if strings.Contains(events[0].Payload, secret) {
			t.Fatal("secret retained in audit evidence")
		}
		record := storedAuditTest(t, events[0].Payload)
		if record.Decision != "LOG" || record.SyscallName != "connect" || record.RecordID == "" || record.RawRecord.SHA256 == "" {
			t.Fatalf("core fields were omitted: %+v", record)
		}
		if keepRaw {
			if record.RawRecord.Text == "" || !record.RawRecord.Redacted || record.RawRecord.State != "available" {
				t.Fatalf("redacted source missing: %+v", record.RawRecord)
			}
		} else if record.RawRecord.Text != "" || record.RawRecord.State != "omitted" || record.RawRecord.Reason != "capture_policy" {
			t.Fatalf("basic mode retained raw source: %+v", record.RawRecord)
		}
	}
}

func TestAuditIngestAtomicFailureAndRetry(t *testing.T) {
	db, _ := nativeTestStore(t)
	if _, err := db.Exec(`CREATE TRIGGER reject_audit BEFORE INSERT ON telemetry_batches BEGIN SELECT RAISE(ABORT,'fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	opts := AuditIngestOptions{RunID: "run", Source: auditTestSource}
	r, err := IngestAuditReader(context.Background(), db, opts, strings.NewReader(auditTestSeccomp))
	if err == nil || r.Ingested != 0 || r.Read != 0 {
		t.Fatalf("partial transaction acknowledged: %+v %v", r, err)
	}
	for _, table := range []string{"events", "telemetry_batches", "telemetry_event_windows", "graph_edges"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial %s count=%d err=%v", table, count, err)
		}
	}
	if _, err := db.Exec(`DROP TRIGGER reject_audit`); err != nil {
		t.Fatal(err)
	}
	if r, err := IngestAuditReader(context.Background(), db, opts, strings.NewReader(auditTestSeccomp)); err != nil || r.Ingested != 1 {
		t.Fatalf("retry=%+v err=%v", r, err)
	}
}

func TestAuditIngestConcurrentDuplicateDelivery(t *testing.T) {
	db, _ := nativeTestStore(t)
	var wg sync.WaitGroup
	results := make(chan AuditIngestResult, 2)
	errors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := IngestAuditReader(context.Background(), db, AuditIngestOptions{RunID: "run", Source: auditTestSource}, strings.NewReader(auditTestSeccomp))
			results <- r
			errors <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	ingested, duplicates := 0, 0
	for r := range results {
		ingested += r.Ingested
		duplicates += r.Duplicates
	}
	if ingested != 1 || duplicates != 1 {
		t.Fatalf("ingested=%d duplicates=%d", ingested, duplicates)
	}
}

func TestAuditIngestBoundedSummaryAndPartialInput(t *testing.T) {
	db, _ := nativeTestStore(t)
	var input strings.Builder
	for i := 0; i < 1100; i++ {
		fmt.Fprintf(&input, "type=SECCOMP msg=audit(1792342593.757:%d): pid=42 arch=c00000b7 syscall=203 code=0x7ffc0000\n", i+1)
	}
	opts := AuditIngestOptions{RunID: "run", Source: auditTestSource}
	r, err := IngestAuditReader(context.Background(), db, opts, strings.NewReader(input.String()))
	if err != nil || r.Ingested != 1100 || r.Batches != 9 || len(r.Rows) != 1000 || !r.RowsTruncated {
		t.Fatalf("unbounded/incomplete summary: ingested=%d batches=%d rows=%d truncated=%v err=%v", r.Ingested, r.Batches, len(r.Rows), r.RowsTruncated, err)
	}
	firstLine := strings.SplitN(input.String(), "\n", 2)[0]
	r, err = IngestAuditReader(context.Background(), db, opts, strings.NewReader(firstLine+"\n"+strings.Repeat("x", MaxAuditLineBytes+1)))
	if err == nil || r.Read != 1 || r.Duplicates != 1 || r.FileSHA256 != "" {
		t.Fatalf("oversize handling=%+v err=%v", r, err)
	}
	r, err = IngestAuditReader(context.Background(), db, opts, strings.NewReader(strings.Repeat("type=SECCOMP msg=audit(bad)\n", 25)))
	if err != nil || r.Failed != 25 || len(r.Errors) != 20 || !r.ErrorsTruncated || r.Status != "partial" {
		t.Fatalf("parse errors lost/unbounded: %+v err=%v", r, err)
	}
}

func storedAuditTest(t *testing.T, payload string) AuditRecord {
	t.Helper()
	body, err := decodePayloadObject(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(unwrapStoredPayload(body))
	if err != nil {
		t.Fatal(err)
	}
	var record AuditRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestAuditIngestKeepsSourcesIndependentAndMissingIdentityVisible(t *testing.T) {
	db, _ := nativeTestStore(t)
	input := auditTestSeccomp + "\n" + `type=AVC msg=audit(1792342593.757:131): apparmor="DENIED" operation="open" pid=42 name="/tmp/secret"`
	r, err := IngestAuditReader(context.Background(), db, AuditIngestOptions{RunID: "run", Mechanism: "apparmor"}, strings.NewReader(input))
	if err != nil || r.Ingested != 1 || r.Skipped != 1 || r.IdentityIncomplete != 1 {
		t.Fatalf("source filtering=%+v err=%v", r, err)
	}
	r, err = IngestAuditReader(context.Background(), db, AuditIngestOptions{RunID: "run", Mechanism: "seccomp"}, strings.NewReader(input))
	if err != nil || r.Ingested != 1 || r.Skipped != 1 || r.IdentityIncomplete != 1 {
		t.Fatalf("source filtering=%+v err=%v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := IngestAuditReader(ctx, db, AuditIngestOptions{RunID: "run"}, strings.NewReader(input)); err == nil {
		t.Fatal("cancelled import continued")
	}
}

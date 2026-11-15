package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
)

func secCheckReplayBatch(t *testing.T) ([]byte, seccheck.Target) {
	t.Helper()
	db, paths := nativeTestStore(t)
	s, err := NewSecCheckStream(db, paths, NativeStreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r := secCheckTestRecord(t, &wire.Open{ContextData: secCheckTestContext(), Pathname: "/work/history.csv"}, wire.MessageType_MESSAGE_SYSCALL_OPEN, 1)
	for i, run := range []string{"run-a", "run-b"} {
		r.Sequence = uint64(i)
		if err := s.Sink(run, r.Registration)(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	var path string
	if err := db.QueryRow(`SELECT spool_path FROM telemetry_spool_batches WHERE format='gvisor_seccheck'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	uploader := seccheck.Target{RunID: "clone-run", SocketPath: "/tmp/current.sock", Registration: r.Registration}
	uploader.Registration.InstanceID = "clone-a"
	return raw, uploader
}

func secCheckReplay(t *testing.T, db *sql.DB, raw []byte, target seccheck.Target) SecCheckReplayResult {
	t.Helper()
	r, err := ReplaySecCheckSpool(context.Background(), db, bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw)), target)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSecCheckReplayClonesPreserveHistoryAndReceipts(t *testing.T) {
	raw, uploader := secCheckReplayBatch(t)
	db, _ := nativeTestStore(t)
	first := secCheckReplay(t, db, raw, uploader)
	if len(first.Receipts) != 2 || len(first.Reused) != 0 {
		t.Fatalf("first result: %+v", first)
	}
	before := map[string]EventRecord{}
	for _, receipt := range first.Receipts {
		if receipt.Ingested != 1 || receipt.Duplicates != 0 || receipt.Uploader.InstanceID != "clone-a" {
			t.Fatalf("first receipt: %+v", receipt)
		}
		for _, id := range receipt.EventIDs {
			e, err := eventRecordByID(db, id)
			if err != nil {
				t.Fatal(err)
			}
			sentry, err := readSecCheckEvidence(e.Payload)
			if err != nil || sentry.Registration.InstanceID != "node" || e.CreatedAt != "2027-01-15T08:00:00.000000111Z" {
				t.Fatalf("rewrote history: %+v %v", e, err)
			}
			before[id] = e
		}
	}
	uploader.Registration.InstanceID = "clone-b"
	second := secCheckReplay(t, db, raw, uploader)
	for i, receipt := range second.Receipts {
		if receipt.Ingested != 0 || receipt.Duplicates != 1 || receipt.ReceiptID == first.Receipts[i].ReceiptID || !reflect.DeepEqual(receipt.EventIDs, first.Receipts[i].EventIDs) {
			t.Fatalf("clone receipt: %+v", receipt)
		}
		stored, err := eventRecordByID(db, receipt.ReceiptID)
		if err != nil || ValidateSecCheckStoredEvent(stored) != nil {
			t.Fatalf("invalid receipt: %+v %v", stored, err)
		}
	}
	third := secCheckReplay(t, db, raw, uploader)
	if !reflect.DeepEqual(third.Receipts, second.Receipts) || len(third.Reused) != 2 {
		t.Fatalf("retry changed receipts: %+v", third)
	}
	for id, original := range before {
		after, err := eventRecordByID(db, id)
		if err != nil || !reflect.DeepEqual(after, original) {
			t.Fatalf("replay changed historical event: %+v %v", after, err)
		}
	}
	var events int
	if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&events); err != nil || events != 6 {
		t.Fatalf("events=%d err=%v", events, err)
	}
}

func TestSecCheckReplayRejectsInvalidBatchAtomically(t *testing.T) {
	raw, uploader := secCheckReplayBatch(t)
	mutate := func(change func(*IngestEvent)) []byte {
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		var event IngestEvent
		if err := json.Unmarshal(lines[1], &event); err != nil {
			t.Fatal(err)
		}
		change(&event)
		lines[1], _ = json.Marshal(event)
		return append(bytes.Join(lines, []byte("\n")), '\n')
	}
	for name, input := range map[string][]byte{
		"truncated":      raw[:len(raw)-1],
		"invalid_json":   append(append([]byte{}, raw...), []byte("{bad}\n")...),
		"too_many_rows":  bytes.Repeat(append(bytes.Split(raw, []byte("\n"))[0], '\n'), 4097),
		"too_many_bytes": bytes.Repeat([]byte("x"), (16<<20)+1),
		"changed_raw_id": mutate(func(e *IngestEvent) { e.RawEventID = "seccheck:forged" }),
		"changed_birth": mutate(func(e *IngestEvent) {
			e.Payload = strings.Replace(e.Payload, "1800000000000000001", "1800000000000000002", 1)
			e.ContainerID = "forged"
		}),
		"borrowed_host": mutate(func(e *IngestEvent) { e.CgroupID = "same-number" }),
		"extra_binding": mutate(func(e *IngestEvent) { e.AttemptID = "other" }),
		"foreign_namespace": mutate(func(e *IngestEvent) {
			e.Payload = strings.Replace(e.Payload, `"namespace":"lab"`, `"namespace":"foreign"`, 1)
		}),
	} {
		t.Run(name, func(t *testing.T) {
			db, _ := nativeTestStore(t)
			_, err := ReplaySecCheckSpool(context.Background(), db, bytes.NewReader(input), fmt.Sprintf("%x", sha256.Sum256(input)), uploader)
			if err == nil {
				t.Fatal("invalid batch accepted")
			}
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("partial evidence: %d %v", count, err)
			}
		})
	}
	for _, digest := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64)} {
		db, _ := nativeTestStore(t)
		if _, err := ReplaySecCheckSpool(context.Background(), db, bytes.NewReader(raw), digest, uploader); err == nil {
			t.Fatal("invalid digest accepted")
		}
	}
}

func TestSecCheckReplayConflictAndReceiptFailureRollback(t *testing.T) {
	raw, uploader := secCheckReplayBatch(t)
	for _, mode := range []string{"receipt_failure", "identity_conflict", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := nativeTestStore(t)
			ctx := context.Background()
			if mode == "receipt_failure" {
				if _, err := db.Exec(`CREATE TRIGGER fail_replay BEFORE INSERT ON events WHEN json_extract(NEW.payload,'$.spool_replay') IS NOT NULL BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			} else if mode == "identity_conflict" {
				first := secCheckReplay(t, db, raw, uploader)
				if _, err := db.Exec(`UPDATE events SET payload='{}' WHERE id=?`, first.Receipts[1].EventIDs[0]); err != nil {
					t.Fatal(err)
				}
				uploader.Registration.Generation = "2"
			} else {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var before int
			if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := ReplaySecCheckSpool(ctx, db, bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw)), uploader); err == nil {
				t.Fatal("failure acknowledged")
			}
			var after int
			if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&after); err != nil || before != after {
				t.Fatalf("partial receipt/evidence: %d -> %d %v", before, after, err)
			}
		})
	}
}

func TestSecCheckReplayConcurrentRetries(t *testing.T) {
	raw, uploader := secCheckReplayBatch(t)
	db, _ := nativeTestStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ReplaySecCheckSpool(context.Background(), db, bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw)), uploader); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("retry count=%d %v", count, err)
	}
}

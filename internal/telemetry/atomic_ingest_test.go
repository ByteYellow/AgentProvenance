package telemetry

import (
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

func TestIngestFilteredRollsBackEveryRequiredWrite(t *testing.T) {
	for _, target := range []string{"graph_edges", "evidence_events", "execution_context_bindings", "snapshots"} {
		t.Run(target, func(t *testing.T) {
			db, _ := nativeTestStore(t)
			event := IngestEvent{RunID: "run", SessionID: "session", ToolCallID: "tool", ProcessID: "process", PID: 4242, EventType: "execve", Payload: `{"argv":["echo","ok"]}`, Timestamp: "2026-01-01T00:01:00Z"}
			operation := "INSERT"
			switch target {
			case "evidence_events":
				event.AttemptID = "attempt"
			case "execution_context_bindings":
				operation = "UPDATE"
				event.EventType, event.Payload = "process_exit", `{"exit_code":0}`
				if _, err := correlation.RecordBinding(db, correlation.Binding{RunID: "run", SessionID: "session", PID: 4242, StartedAt: "2026-01-01T00:00:00Z"}); err != nil {
					t.Fatal(err)
				}
			case "snapshots":
				operation = "UPDATE"
				event.SnapshotID, event.EventType, event.Payload = "snapshot", "secret_path", `{"path":"/tmp/credentials"}`
				if _, err := db.Exec(`INSERT INTO snapshots(id,path,manifest_hash,file_count,bytes,status,created_at) VALUES ('snapshot','/tmp/snapshot','hash',0,0,'ready','2026-01-01T00:00:00Z')`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`CREATE TRIGGER fail_write BEFORE ` + operation + ` ON ` + target + ` BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
				t.Fatal(err)
			}
			id, err := IngestFiltered(db, event)
			if err == nil || id != "" || !strings.Contains(err.Error(), "injected failure") {
				t.Fatalf("partial write acknowledged: id=%q err=%v", id, err)
			}
			for _, table := range []string{"events", "graph_edges", "evidence_events"} {
				var count int
				if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("partial %s: count=%d err=%v", table, count, err)
				}
			}
			if _, err := db.Exec(`DROP TRIGGER fail_write`); err != nil {
				t.Fatal(err)
			}
			if _, err := IngestFiltered(db, event); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
		})
	}
}

func TestIngestFilteredPreservesCaptureTime(t *testing.T) {
	db, _ := nativeTestStore(t)
	for _, captured := range []string{"2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000001Z", "2026-01-01T08:00:00+08:00", ""} {
		before := time.Now().UTC()
		id, err := IngestFiltered(db, IngestEvent{RunID: "run", SessionID: "session", ToolCallID: "tool", ProcessID: "process", EventType: "execve", Payload: `{"argv":["echo"]}`, Timestamp: captured})
		if err != nil {
			t.Fatal(err)
		}
		var stored string
		if err := db.QueryRow(`SELECT created_at FROM events WHERE id=?`, id).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if captured != "" && stored != captured {
			t.Fatalf("capture=%q stored=%q", captured, stored)
		}
		if captured == "" {
			at, err := time.Parse(time.RFC3339Nano, stored)
			if err != nil || at.Before(before) || at.After(time.Now()) {
				t.Fatalf("invalid default capture time: %q (%v)", stored, err)
			}
		}
	}
	if _, err := IngestFiltered(db, IngestEvent{EventType: "execve", Timestamp: "invalid", Payload: `{"argv":["echo"]}`}); err == nil {
		t.Fatal("invalid capture time accepted")
	}
}

func TestFalcoBatchFailedRowLeavesNoPartialEvidence(t *testing.T) {
	db, _ := nativeTestStore(t)
	if _, err := db.Exec(`CREATE TRIGGER fail_first_row BEFORE INSERT ON graph_edges WHEN NEW.from_id='runtime_process/pid/4242' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	input := `{"time":"2026-01-01T00:00:00Z","output_fields":{"evt.type":"execve","proc.pid":4242,"proc.cmdline":"echo bad"}}
{"time":"2026-01-01T00:00:01Z","output_fields":{"evt.type":"execve","proc.pid":4243,"proc.cmdline":"echo good"}}`
	result, err := IngestFalco(db, FalcoIngestOptions{RunID: "run"}, strings.NewReader(input))
	if err != nil || result.Ingested != 1 || result.Failed != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE pid=4242`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed row persisted: count=%d err=%v", count, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE from_id='runtime_process/pid/4242' OR to_id='runtime_process/pid/4242'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed row edges persisted: count=%d err=%v", count, err)
	}
}

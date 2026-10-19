package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

var auditAssociationTime = time.Unix(1792342593, 757000000).UTC()

const associationBoot = "01234567-89ab-cdef-0123-456789abcdef"

func auditRuntimeFixture(id string, offset time.Duration, stage string) auditRuntime {
	start := uint64(1000000000)
	mono := uint64(int64(10*time.Second) + int64(offset))
	nr := int64(203)
	f := auditRuntimeFields{HostID: "fixture-host", BootID: associationBoot,
		CoarseClockNS: int64(4 * time.Millisecond),
		Instance:      associationBoot + ":42:1000000000", Start: strconv.FormatUint(start, 10),
		Monotonic: strconv.FormatUint(mono, 10), TID: 43, Thread: associationBoot + ":43:1000000000",
		ThreadStart: strconv.FormatUint(start, 10), Comm: "fixture"}
	e := auditRuntime{id: id, pid: 42, at: auditAssociationTime.Add(offset), mono: mono, etype: "execve"}
	if stage != "" {
		f.OperationID = "syscall-v1:" + f.Thread + ":42:1000000000:10000100000"
		f.Operation, f.Stage, f.SyscallStart, f.SyscallNumber, f.Arch = "network_connect", stage, "10000100000", &nr, "arm64"
		e.etype = "network_connect"
		if stage == "result" || stage == "attempt_and_result" {
			result := int64(0)
			f.Result, f.Outcome, e.etype = &result, "success", "syscall_result"
		}
	}
	e.fields = f
	return e
}

func auditInputFixture(t *testing.T) auditAssociationInput {
	t.Helper()
	record, ok, err := ParseAuditLine([]byte(`type=SECCOMP msg=audit(1792342593.757:130): pid=42 comm="fixture" arch=c00000b7 syscall=203 code=0x7ffc0000`),
		AuditSource{HostID: "fixture-host", BootID: associationBoot})
	if err != nil || !ok {
		t.Fatal(err)
	}
	return auditAssociationInput{id: "audit", record: record}
}

func auditRuntimeSet() []auditRuntime {
	return []auditRuntime{auditRuntimeFixture("before", -5*time.Millisecond, ""),
		auditRuntimeFixture("entry", 100*time.Microsecond, "attempt"),
		auditRuntimeFixture("result", 200*time.Microsecond, "result"),
		auditRuntimeFixture("after", 5*time.Millisecond, "")}
}

func TestAuditAssociatesLifetimeAndOneOperation(t *testing.T) {
	events := auditRuntimeSet()
	events[1].context = AuditContextRef{EventID: "entry", SessionID: "session-one", ToolCallID: "tool-one", Method: "command_match", Confidence: 0.8}
	item := associateAudit(auditInputFixture(t), indexAuditRuntime(events))
	if item.Process.Status != "inferred" || item.Operation.Status != "inferred" || len(item.Operations) != 1 {
		t.Fatalf("association=%+v", item)
	}
	op := item.Operations[0]
	if op.AttemptCount != 1 || op.ResultCount != 1 || op.Result == nil || *op.Result != 0 || len(op.Context) != 1 || op.Context[0].Method != "command_match" {
		t.Fatalf("operation/context changed: %+v", op)
	}
	if !reflect.DeepEqual(op.AttemptRefs, []string{"runtime_event/entry"}) || !reflect.DeepEqual(op.ResultRefs, []string{"runtime_event/result"}) {
		t.Fatalf("source refs lost: %+v", op)
	}
	// Two distinct mechanisms may reference one operation. There is still one
	// operation identity, not an extra runtime behavior for each audit record.
	other := auditInputFixture(t)
	other.id = "other-decision"
	if got := associateAudit(other, indexAuditRuntime(events)); got.Operations[0].ID != op.ID {
		t.Fatal("decision inflated operation identity")
	}
}

func TestAuditNeverChoosesNearestConcurrentCall(t *testing.T) {
	events := auditRuntimeSet()
	second := auditRuntimeFixture("second-entry", 300*time.Microsecond, "attempt")
	second.fields.TID, second.fields.Thread = 44, associationBoot+":44:1000000000"
	second.fields.SyscallStart = "10000300000"
	second.fields.OperationID = "syscall-v1:" + second.fields.Thread + ":42:1000000000:10000300000"
	events = append(events, second)
	item := associateAudit(auditInputFixture(t), indexAuditRuntime(events))
	if item.Process.Status != "inferred" || item.Operation.Status != "ambiguous" || item.Operation.CandidateCount != 2 {
		t.Fatalf("concurrent calls were guessed: %+v", item)
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	if got := associateAudit(auditInputFixture(t), indexAuditRuntime(events)); !reflect.DeepEqual(got, item) {
		t.Fatal("arrival order changed association")
	}
}

func TestAuditAssociationMissingAndConflictingEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*auditAssociationInput, *[]auditRuntime)
		p, o   string
	}{
		{"no host", func(a *auditAssociationInput, e *[]auditRuntime) { a.record.HostID = "" }, "unassociated", "unassociated"},
		{"no source clock", func(a *auditAssociationInput, e *[]auditRuntime) {
			for i := range *e {
				(*e)[i].fields.CoarseClockNS = 0
			}
		}, "unassociated", "unassociated"},
		{"other host", func(a *auditAssociationInput, e *[]auditRuntime) { a.record.HostID = "other" }, "unassociated", "unassociated"},
		{"other boot", func(a *auditAssociationInput, e *[]auditRuntime) {
			a.record.BootID = "11234567-89ab-cdef-0123-456789abcdef"
		}, "unassociated", "unassociated"},
		{"other pid", func(a *auditAssociationInput, e *[]auditRuntime) { pid := int64(43); a.record.AuditPID = &pid }, "unassociated", "unassociated"},
		{"no bracket", func(a *auditAssociationInput, e *[]auditRuntime) { *e = (*e)[1:2] }, "unassociated", "unassociated"},
		{"past lifetime", func(a *auditAssociationInput, e *[]auditRuntime) {
			a.record.Timestamp = auditAssociationTime.Add(time.Hour).Format(time.RFC3339Nano)
		}, "unassociated", "unassociated"},
		{"clock step", func(a *auditAssociationInput, e *[]auditRuntime) { (*e)[3].at = (*e)[3].at.Add(time.Second) }, "unassociated", "unassociated"},
		{"unknown abi", func(a *auditAssociationInput, e *[]auditRuntime) { a.record.ABI = "unknown" }, "inferred", "unassociated"},
		{"other syscall", func(a *auditAssociationInput, e *[]auditRuntime) { nr := int64(999); a.record.SyscallNumber = &nr }, "inferred", "unassociated"},
		{"other comm", func(a *auditAssociationInput, e *[]auditRuntime) { a.record.Comm = "changed" }, "inferred", "unassociated"},
		{"malformed operation id", func(a *auditAssociationInput, e *[]auditRuntime) {
			(*e)[1].fields.OperationID = "wrong"
			(*e)[2].fields.OperationID = "wrong"
		}, "inferred", "unassociated"},
		{"runtime lifetime missing", func(a *auditAssociationInput, e *[]auditRuntime) { (*e)[1].fields.Start = "" }, "unassociated", "unassociated"},
		{"status record", func(a *auditAssociationInput, e *[]auditRuntime) { a.record.EvidenceKind = "audit_status" }, "unassociated", "unassociated"},
		{"result conflict", func(a *auditAssociationInput, e *[]auditRuntime) {
			other := (*e)[2]
			other.id = "conflicting-result"
			result := int64(-1)
			other.fields.Result = &result
			*e = append(*e, other)
		}, "inferred", "ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, events := auditInputFixture(t), auditRuntimeSet()
			tc.change(&a, &events)
			item := associateAudit(a, indexAuditRuntime(events))
			if item.Process.Status != tc.p || item.Operation.Status != tc.o {
				t.Fatalf("association=%+v", item)
			}
		})
	}
}

func TestAuditPIDReuseWithinRoundedTimestampIsAmbiguous(t *testing.T) {
	var events []auditRuntime
	for i, start := range []string{"1000000000", "10000400000"} {
		for j := 0; j < 2; j++ {
			e := auditRuntimeFixture(fmt.Sprintf("life-%d-%d", i, j), time.Duration(i*600+j*100)*time.Microsecond, "")
			e.fields.Start, e.fields.Instance = start, associationBoot+":42:"+start
			events = append(events, e)
		}
	}
	item := associateAudit(auditInputFixture(t), indexAuditRuntime(events))
	if item.Process.Status != "ambiguous" || item.Process.CandidateCount != 2 || item.Operation.Status != "unassociated" {
		t.Fatalf("reused PID guessed: %+v", item)
	}
	// At finer audit precision only the second lifetime brackets the record.
	a := auditInputFixture(t)
	a.record.Timestamp, a.record.TimestampPrecisionNS = auditAssociationTime.Add(650*time.Microsecond).Format(time.RFC3339Nano), 1000
	item = associateAudit(a, indexAuditRuntime(events))
	if item.Process.Status != "inferred" || !strings.HasSuffix(item.Process.Candidates[0].ID, ":10000400000") {
		t.Fatalf("fine precision did not select lifetime: %+v", item)
	}
}

func TestAuditAppArmorPathRequiresExactEvidence(t *testing.T) {
	a := auditInputFixture(t)
	a.record.Mechanism, a.record.Operation, a.record.Target = "apparmor", "open", "/tmp/secret"
	events := auditRuntimeSet()
	for i := 1; i <= 2; i++ {
		events[i].fields.Operation, events[i].fields.Path = "file_open", "/tmp/secret"
	}
	if got := associateAudit(a, indexAuditRuntime(events)); got.Operation.Status != "inferred" {
		t.Fatalf("exact path not matched: %+v", got)
	}
	for _, target := range []string{"secret", "/tmp/secret-suffix", "/tmp/../tmp/secret", ""} {
		a.record.Target = target
		if got := associateAudit(a, indexAuditRuntime(events)); got.Operation.Status != "unassociated" {
			t.Fatalf("guessed target %q: %+v", target, got)
		}
	}
}

func TestAuditKillHasExitWithoutInventedOperation(t *testing.T) {
	a := auditInputFixture(t)
	a.record.Decision = "KILL_PROCESS"
	events := auditRuntimeSet()
	events = []auditRuntime{events[0], events[3]}
	events[1].etype, events[1].fields.ExitScope = "process_exit", "thread_group"
	item := associateAudit(a, indexAuditRuntime(events))
	if item.Process.Status != "inferred" || item.Operation.Status != "unassociated" || len(item.ProcessExits) != 1 || len(item.Operations) != 0 {
		t.Fatalf("kill invented syscall return: %+v", item)
	}
	events[1].etype, events[1].fields.ExitScope = "thread_exit", "thread"
	if got := associateAudit(a, indexAuditRuntime(events)); len(got.ProcessExits) != 0 {
		t.Fatal("thread exit was treated as final process exit")
	}
}

func storeAuditRuntimeFixtures(t *testing.T, db *sql.DB, events []auditRuntime, run string) {
	t.Helper()
	for _, e := range events {
		raw, err := json.Marshal(e.fields)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		body["command"], body["dst_ip"] = "fixture", "127.0.0.1"
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ingestFilteredWithID(db, IngestEvent{RunID: run, Source: "agentprov_ebpf", EventType: e.etype,
			PID: e.pid, TGID: e.pid, Timestamp: e.at.Format(time.RFC3339Nano), Payload: string(raw)}, e.id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditAssociationReadSnapshotPagingAndLateEvidence(t *testing.T) {
	db, _ := nativeTestStore(t)
	input := auditInputFixture(t)
	line := input.record.RawRecord.Text
	opts := AuditIngestOptions{RunID: "run", Source: input.record.AuditSource}
	if r, err := IngestAuditReader(context.Background(), db, opts, strings.NewReader(line+"\n"+strings.Replace(line, ":130)", ":131)", 1))); err != nil || r.Ingested != 2 {
		t.Fatalf("ingest=%+v %v", r, err)
	}
	before, err := ListEvents(db, "run", "")
	if err != nil {
		t.Fatal(err)
	}
	page, err := BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: "run", Limit: 1})
	if err != nil || len(page.Items) != 1 || !page.HasMore || page.NextCursor == "" || page.Items[0].Process.Status != "unassociated" {
		t.Fatalf("first page=%+v %v", page, err)
	}
	storeAuditRuntimeFixtures(t, db, auditRuntimeSet(), "run")
	db.SetMaxOpenConns(1)
	page, err = BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: "run", Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(page.Items) != 1 || page.HasMore || page.Items[0].Operation.Status != "inferred" {
		t.Fatalf("late evidence=%+v %v", page, err)
	}
	for _, cursor := range []string{"bad", strings.Repeat("a", 4097), page.NextCursor + "invalid"} {
		if _, err := BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: "other", Cursor: cursor}); err == nil {
			t.Fatal("invalid cursor accepted")
		}
	}
	after, err := ListEventsFiltered(db, Filter{RunID: "run", Type: "access_control"})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("projection rewrote audit evidence: %+v %v", after, err)
	}
	// Late concurrent evidence must revoke the earlier unique inference.
	second := auditRuntimeFixture("second-entry", 300*time.Microsecond, "attempt")
	second.fields.SyscallStart = "10000300000"
	second.fields.OperationID = "syscall-v1:" + second.fields.Thread + ":42:1000000000:10000300000"
	storeAuditRuntimeFixtures(t, db, []auditRuntime{second}, "run")
	page, err = BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: "run"})
	if err != nil || len(page.Items) != 2 || page.Items[0].Operation.Status != "ambiguous" || page.Items[1].Operation.Status != "ambiguous" {
		t.Fatalf("stale association survived late evidence: %+v %v", page, err)
	}
}

func TestAuditAssociationFailureDoesNotBecomeMissingEvidence(t *testing.T) {
	db, _ := nativeTestStore(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: "run"}); err == nil {
		t.Fatal("closed database returned a successful empty report")
	}
}

func TestAuditAssociationRuntimeLimitsDisableInference(t *testing.T) {
	for _, mode := range []string{"row_count", "payload_size"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := nativeTestStore(t)
			input := auditInputFixture(t)
			if _, err := IngestAuditReader(context.Background(), db, AuditIngestOptions{RunID: "run", Source: input.record.AuditSource}, strings.NewReader(input.record.RawRecord.Text)); err != nil {
				t.Fatal(err)
			}
			storeAuditRuntimeFixtures(t, db, auditRuntimeSet(), "run")
			count, payload := maxAuditRuntimeRows, "{}"
			if mode == "payload_size" {
				count, payload = 1, `{"command":"`+strings.Repeat("x", 65536)+`"}`
			}
			if _, err := db.Exec(`WITH RECURSIVE seq(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM seq WHERE i<?)
				INSERT INTO events(id,run_id,pid,source,event_type,payload,created_at)
				SELECT 'limit-'||i,'run',42,'agentprov_ebpf','execve',?,? FROM seq`, count, payload, auditAssociationTime.Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			report, err := BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: "run"})
			if err != nil || report.Status != "incomplete" || len(report.Items) != 1 || report.Items[0].Process.Reason != "runtime_input_limit" || len(report.Items[0].Operations) != 0 {
				t.Fatalf("truncated input produced inference: %+v %v", report, err)
			}
		})
	}
}

func TestAuditClockResolutionAndRoundedBoundaries(t *testing.T) {
	input := auditInputFixture(t)
	events := auditRuntimeSet()
	// A coarse timestamp can precede the entry even though both display ms.
	input.record.Timestamp = auditAssociationTime.Add(-3 * time.Millisecond).Format(time.RFC3339Nano)
	item := associateAudit(input, indexAuditRuntime(events))
	if item.Operation.Status != "inferred" || item.TimeWindow == nil || item.TimeWindow.CoarseClockResolution != int64(4*time.Millisecond) {
		t.Fatalf("coarse kernel clock discarded valid candidate: %+v", item)
	}
	events[0].fields.CoarseClockNS = 1000000
	if got := associateAudit(input, indexAuditRuntime(events)); got.Process.Reason != "source_clock_resolution_conflict" {
		t.Fatalf("contradicting clocks accepted: %+v", got)
	}
}

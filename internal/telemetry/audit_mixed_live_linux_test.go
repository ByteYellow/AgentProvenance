//go:build linux && (amd64 || arm64)

package telemetry

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
	"github.com/byteyellow/agentprovenance/internal/ids"
)

//go:embed testdata/audit_mixed.c
var auditMixedProgram string

type auditMixedObservation struct {
	Case          string                 `json:"case"`
	PID           int64                  `json:"pid"`
	TID           int64                  `json:"tid"`
	SyscallNumber int64                  `json:"syscall_number"`
	FilterAction  uint32                 `json:"filter_action"`
	FilterFlags   uint32                 `json:"filter_flags"`
	Result        int64                  `json:"result"`
	Errno         int                    `json:"errno"`
	State         accesscontrol.Snapshot `json:"state"`
}

func TestLiveAccessControlMixedMatrix(t *testing.T) {
	if os.Getenv("AGENTPROV_AUDIT_MIXED_LIVE") != "1" {
		t.Skip("set AGENTPROV_AUDIT_MIXED_LIVE=1 on a disposable Linux test host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("mixed access-control fixture requires root")
	}
	for _, tool := range []string{"cc", "apparmor_parser", "aa-exec", "journalctl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	loggedBefore, err := os.ReadFile("/proc/sys/kernel/seccomp/actions_logged")
	if err != nil || !strings.Contains(" "+strings.TrimSpace(string(loggedBefore))+" ", " errno ") {
		t.Fatalf("existing kernel logging must allow errno; no host setting is changed: %v", err)
	}
	dir := t.TempDir()
	bin, source, target := filepath.Join(dir, "probe"), filepath.Join(dir, "probe.c"), filepath.Join(dir, "fixture.secret")
	for name, body := range map[string]string{source: auditMixedProgram, target: "public mixed-mechanism fixture\n"} {
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	liveAuditCommand(t, "cc", "-static", "-O2", "-Wall", "-Werror", "-o", bin, source)
	prefix := ids.New("agentprov-mixed-fixture")
	profiles := fmt.Sprintf("profile %s-enforce { %q rix, /proc/** r, signal, ptrace, }\nprofile %s-complain flags=(complain) { %q rix, /proc/** r, signal, ptrace, }\n", prefix, bin, prefix, bin)
	policyPath := filepath.Join(dir, "profiles")
	if err := os.WriteFile(policyPath, []byte(profiles), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		liveAuditCommand(t, "apparmor_parser", "-K", "-R", policyPath)
		active, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
		if err != nil || bytes.Contains(active, []byte(prefix)) {
			t.Errorf("mixed fixture profiles were not removed: %v", err)
		}
		loggedAfter, err := os.ReadFile("/proc/sys/kernel/seccomp/actions_logged")
		if err != nil || !bytes.Equal(loggedBefore, loggedAfter) {
			t.Errorf("host seccomp logging changed during fixture: %v", err)
		}
	})
	liveAuditCommand(t, "apparmor_parser", "-K", "-a", policyPath)
	var journalStart struct {
		Cursor string `json:"__CURSOR"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(liveAuditCommand(t, "journalctl", "-k", "-n", "1", "-o", "json", "--no-pager")), &journalStart); err != nil || journalStart.Cursor == "" {
		t.Fatalf("journal cursor unavailable: %v", err)
	}
	finishSensor := startLiveAuditSensor(t)
	cases := []struct {
		name, profile, filter string
		wantErrno             int
	}{
		{"log-denied", "enforce", "log", 13},
		{"log-allowed", "complain", "log", 0},
		{"errno-enforce", "enforce", "errno", 1},
		{"errno-complain", "complain", "errno", 1},
		{"silent-errno", "", "silent-errno", 1},
		{"ordinary-permission", "", "plain", 13},
	}
	observations := map[int64]auditMixedObservation{}
	var pids []int64
	var states bytes.Buffer
	for _, tc := range cases {
		profile := ""
		if tc.profile != "" {
			profile = prefix + "-" + tc.profile
		}
		observed := runAuditMixedFixture(t, bin, target, profile, tc.filter)
		observed.Case = tc.name
		if observed.Errno != tc.wantErrno || tc.wantErrno != 0 && observed.Result != -1 || tc.wantErrno == 0 && observed.Result < 0 {
			t.Fatalf("independent result %s: %+v", tc.name, observed)
		}
		if tc.profile != "" && (observed.State.AppArmor.Mode != tc.profile || !strings.Contains(observed.State.AppArmor.Label, profile)) {
			t.Fatalf("actual AppArmor state %s: %+v", tc.name, observed.State)
		}
		if tc.filter != "plain" && (observed.State.Seccomp.Status != "observed" || observed.State.Seccomp.Mode != "filter") {
			t.Fatalf("actual seccomp state %s: %+v", tc.name, observed.State)
		}
		if _, reused := observations[observed.PID]; reused {
			t.Fatal("fixture PIDs reused inside the journal capture window")
		}
		observations[observed.PID] = observed
		pids = append(pids, observed.PID)
		if err := json.NewEncoder(&states).Encode(map[string]any{"source": "procfs_access_control", "event_type": "access_control_state", "state": observed.State, "timestamp": observed.State.ObservedAt}); err != nil {
			t.Fatal(err)
		}
	}
	runtime := finishSensor(pids)
	results := map[string]int{}
	scanner := bufio.NewScanner(bytes.NewReader(runtime))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var event struct {
			PID int64 `json:"pid"`
			auditRuntimeFields
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		observed := observations[event.PID]
		if event.Path != target || event.Operation != "file_open" || event.Result == nil {
			continue
		}
		want := observed.Result
		if observed.Errno != 0 {
			want = -int64(observed.Errno)
		}
		if *event.Result != want {
			t.Fatalf("native result %s: got=%d want=%d", observed.Case, *event.Result, want)
		}
		results[observed.Case]++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if want := (map[string]int{"log-denied": 1, "log-allowed": 1, "ordinary-permission": 1}); !reflect.DeepEqual(results, want) {
		t.Fatalf("native target results got=%v want=%v", results, want)
	}
	var selected bytes.Buffer
	records := map[string]AuditRecord{}
	counts := map[string]int{}
	deadline := time.Now().Add(3 * time.Second)
	for {
		selected.Reset()
		records, counts = map[string]AuditRecord{}, map[string]int{}
		journal := liveAuditCommand(t, "journalctl", "-k", "--after-cursor", journalStart.Cursor, "-n", "2000", "-o", "json", "--no-pager")
		scanner := bufio.NewScanner(bytes.NewReader(journal))
		scanner.Buffer(make([]byte, 4096), MaxAuditLineBytes)
		for scanner.Scan() {
			record, ok, err := ParseAuditLine(scanner.Bytes(), AuditSource{})
			if err != nil || !ok || record.AuditPID == nil {
				continue
			}
			observed, known := observations[*record.AuditPID]
			if !known || record.Mechanism == "apparmor" && record.Target != target {
				continue
			}
			if record.Mechanism == "seccomp" && (record.SyscallNumber == nil || *record.SyscallNumber != observed.SyscallNumber) {
				t.Fatalf("unexpected syscall in fixture audit: %+v", record)
			}
			if _, duplicate := records[record.RecordID]; duplicate {
				continue
			}
			records[record.RecordID] = record
			counts[observed.Case+"/"+record.Mechanism+"/"+record.Decision]++
			selected.Write(scanner.Bytes())
			selected.WriteByte('\n')
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		// Keep the bounded journal interval open even after the expected records
		// arrive, so delayed records cannot turn a missing source into an allow.
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	want := map[string]int{"log-denied/apparmor/DENIED": 1, "log-denied/seccomp/LOG": 1,
		"log-allowed/apparmor/ALLOWED": 1, "log-allowed/seccomp/LOG": 1,
		"errno-enforce/seccomp/ERRNO": 1, "errno-complain/seccomp/ERRNO": 1}
	// An existing audit policy may also log the silent filter. Preserve the
	// observed decision if present; this test never disables host audit rules.
	if n := counts["silent-errno/seccomp/ERRNO"]; n > 0 {
		want["silent-errno/seccomp/ERRNO"] = 1
	}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("mixed audit decisions got=%v want=%v", counts, want)
	}
	for _, record := range records {
		// Linux logs the masked action, not the filter's errno data. The
		// independent fixture sees EPERM while the recorded low bits are zero.
		if record.Decision == "ERRNO" && (record.ActionCode == nil || *record.ActionCode != 0x50000 || record.ActionData == nil || *record.ActionData != 0) {
			t.Fatalf("ERRNO action/data changed: %+v", record)
		}
		if record.Mechanism == "seccomp" && (record.Target != "" || record.Profile != "") {
			t.Fatalf("seccomp acquired an invented target/profile: %+v", record)
		}
	}
	saveLiveAuditFixture(t, "mixed-runtime.jsonl", runtime)
	saveLiveAuditFixture(t, "mixed-state.jsonl", states.Bytes())
	saveLiveAuditFixture(t, "mixed-journal.jsonl", selected.Bytes())
	db, _ := nativeTestStore(t)
	const run = "live-audit-mixed"
	for _, input := range [][]byte{runtime, states.Bytes()} {
		result, err := IngestJSONLReader(db, JSONLIngestOptions{Format: "auto", RunID: run}, bytes.NewReader(input))
		if err != nil || result.Failed != 0 || result.Ingested == 0 {
			t.Fatalf("live runtime/state ingestion: %+v %v", result, err)
		}
	}
	opts := AuditIngestOptions{RunID: run, RetainRaw: true}
	ingested, err := IngestAuditReader(context.Background(), db, opts, bytes.NewReader(selected.Bytes()))
	if err != nil || ingested.Ingested != len(records) || ingested.IdentityIncomplete != 0 {
		t.Fatalf("live mixed import: %+v %v", ingested, err)
	}
	repeated, err := IngestAuditReader(context.Background(), db, opts, bytes.NewReader(selected.Bytes()))
	if err != nil || repeated.Ingested != 0 || repeated.Duplicates != len(records) {
		t.Fatalf("live mixed duplicates: %+v %v", repeated, err)
	}
	report, err := BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: run})
	if err != nil || report.Status != "complete" || len(report.Items) != len(records) {
		t.Fatalf("live mixed associations: %+v %v", report, err)
	}
	opIDs := map[string]string{}
	for _, item := range report.Items {
		if item.Process.Status != "inferred" || len(item.ProcessExits) != 1 {
			t.Fatalf("missing fixture lifecycle/exit: %+v", item)
		}
		var record AuditRecord
		for _, candidate := range records {
			if auditEventID(run, candidate.RecordID) == item.EventID {
				record = candidate
			}
		}
		if record.AuditPID == nil {
			t.Fatalf("missing original record for %s", item.EventID)
		}
		observed := observations[*record.AuditPID]
		if item.Decision == "ERRNO" {
			if item.Operation.Status != "unassociated" || len(item.Operations) != 0 {
				t.Fatalf("pre-entry ERRNO fabricated a syscall operation: %+v", item)
			}
			continue
		}
		if item.Operation.Status != "inferred" || len(item.Operations) != 1 || item.Operations[0].Result == nil {
			t.Fatalf("mixed call did not uniquely match: %+v", item)
		}
		op := item.Operations[0]
		result := observed.Result
		if observed.Errno != 0 {
			result = -int64(observed.Errno)
		}
		if op.AttemptCount != 1 || op.ResultCount != 1 || *op.Result != result {
			t.Fatalf("mixed runtime outcome changed: %+v fixture=%+v", op, observed)
		}
		if prior := opIDs[observed.Case]; prior != "" && prior != op.ID {
			t.Fatalf("two decisions split one operation: %s %s", prior, op.ID)
		}
		opIDs[observed.Case] = op.ID
	}
	if len(opIDs) != 2 {
		t.Fatalf("expected two shared operations: %v", opIDs)
	}
	manifest, err := json.MarshalIndent(map[string]any{"fixture_profiles": profiles, "observations": observations,
		"source_cursor": journalStart.Cursor, "actions_logged": strings.TrimSpace(string(loggedBefore)),
		"audit_counts": counts, "associations": report, "import": ingested, "repeat": repeated}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	saveLiveAuditFixture(t, "mixed-matrix.json", manifest)
	t.Logf("six live cases; decisions=%v; shared operations=%d; ERRNO has no fabricated entry/return", counts, len(opIDs))
}

func runAuditMixedFixture(t *testing.T, bin, target, profile, filter string) auditMixedObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	name, args := bin, []string{filter, target}
	if profile != "" {
		name, args = "aa-exec", []string{"-p", profile, "--", bin, filter, target}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr auditCommandOutput
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		in.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("mixed fixture %s/%s: %v: %s", profile, filter, err, stderr.String())
		}
	}()
	reader := bufio.NewScanner(out)
	reader.Buffer(make([]byte, 4096), MaxAuditLineBytes)
	var observed auditMixedObservation
	if !reader.Scan() || json.Unmarshal(reader.Bytes(), &observed) != nil || observed.PID <= 0 || observed.TID <= 0 {
		t.Fatalf("mixed fixture readiness missing: %s %v", stderr.String(), reader.Err())
	}
	observed.State = accesscontrol.ReadTask(int(observed.PID), int(observed.TID), accesscontrol.Options{AppArmor: true, Seccomp: true})
	if err := accesscontrol.ValidateSnapshot(observed.State); err != nil || observed.State.Identity.Status != "observed" {
		t.Fatalf("mixed fixture procfs state: %+v %v", observed.State, err)
	}
	if _, err := in.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if !reader.Scan() || json.Unmarshal(reader.Bytes(), &observed) != nil {
		t.Fatalf("mixed fixture result missing: %s %v", stderr.String(), reader.Err())
	}
	if reader.Scan() || reader.Err() != nil {
		t.Fatalf("unexpected fixture output: %v", reader.Err())
	}
	return observed
}

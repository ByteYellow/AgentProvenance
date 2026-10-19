//go:build linux && (amd64 || arm64)

package telemetry

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

//go:embed testdata/audit_adjacent.c
var auditAdjacentProgram string

func TestLiveAuditAdjacentCalls(t *testing.T) {
	if os.Getenv("AGENTPROV_AUDIT_ADJACENT_LIVE") != "1" {
		t.Skip("set AGENTPROV_AUDIT_ADJACENT_LIVE=1 on a disposable Linux host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("live audit capture requires root")
	}
	dir := t.TempDir()
	source, bin := filepath.Join(dir, "adjacent.c"), filepath.Join(dir, "adjacent")
	if err := os.WriteFile(source, []byte(auditAdjacentProgram), 0600); err != nil {
		t.Fatal(err)
	}
	liveAuditCommand(t, "cc", "-static", "-O2", "-Wall", "-Werror", "-o", bin, source)
	var start struct {
		Cursor string `json:"__CURSOR"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(liveAuditCommand(t, "journalctl", "-k", "-n", "1", "-o", "json", "--no-pager")), &start); err != nil || start.Cursor == "" {
		t.Fatalf("journal cursor: %v", err)
	}
	finish := startLiveAuditSensor(t)
	type observation struct {
		PID      int64             `json:"pid"`
		TID      int64             `json:"tid"`
		Syscall  int64             `json:"syscall_number"`
		Action   uint32            `json:"action"`
		Decision string            `json:"decision"`
		Order    string            `json:"order"`
		Calls    []json.RawMessage `json:"calls"`
	}
	observed := map[int64]observation{}
	var pids []int64
	for _, action := range []string{"ERRNO", "TRAP", "TRACE", "USER_NOTIF", "KILL_PROCESS", "KILL_THREAD", "LOG"} {
		for _, order := range []string{"allow-first", "deny-first"} {
			// Pace independent processes below the host journal's audit burst
			// limit. The two calls inside each process remain adjacent.
			time.Sleep(750 * time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			cmd := exec.CommandContext(ctx, bin, action, order)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			var stderr auditCommandOutput
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				cancel()
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(stdout)
			var item observation
			if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &item) != nil || item.PID <= 0 || item.TID != item.PID {
				cancel()
				_ = cmd.Wait()
				t.Fatalf("fixture readiness %s/%s: %s", action, order, stderr.String())
			}
			item.Decision, item.Order = action, order
			_, err = stdin.Write([]byte("x\n"))
			_ = stdin.Close()
			if err != nil {
				cancel()
				_ = cmd.Wait()
				t.Fatal(err)
			}
			for scanner.Scan() {
				item.Calls = append(item.Calls, append(json.RawMessage(nil), scanner.Bytes()...))
			}
			readErr, waitErr := scanner.Err(), cmd.Wait()
			cancel()
			if readErr != nil {
				t.Fatal(readErr)
			}
			kill := strings.HasPrefix(action, "KILL_")
			if kill {
				exit, ok := waitErr.(*exec.ExitError)
				if !ok || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGSYS {
					t.Fatalf("expected SIGSYS: %v", waitErr)
				}
			} else if waitErr != nil {
				t.Fatalf("fixture %s/%s: %v %s", action, order, waitErr, stderr.String())
			}
			wantCalls := 2
			if kill {
				wantCalls = 1
				if order == "deny-first" {
					wantCalls = 0
				}
			}
			if len(item.Calls) != wantCalls {
				t.Fatalf("fixture calls: %+v", item)
			}
			for _, raw := range item.Calls {
				var call struct {
					Filtered bool  `json:"filtered"`
					Result   int64 `json:"result"`
					Errno    int   `json:"errno"`
					Trapped  int   `json:"trapped"`
				}
				if err := json.Unmarshal(raw, &call); err != nil {
					t.Fatal(err)
				}
				wantErrno := 0
				if call.Filtered && action == "ERRNO" {
					wantErrno = 1
				}
				if call.Filtered && (action == "TRAP" || action == "TRACE" || action == "USER_NOTIF") {
					wantErrno = 38
				}
				if call.Errno != wantErrno || wantErrno == 0 && call.Result != 0 || wantErrno != 0 && call.Result != -1 || call.Filtered && action == "TRAP" && call.Trapped != 1 {
					t.Fatalf("independent outcome %s/%s: %s", action, order, raw)
				}
			}
			if _, exists := observed[item.PID]; exists {
				t.Fatal("PID reused during fixture capture")
			}
			observed[item.PID], pids = item, append(pids, item.PID)
		}
	}
	runtime := finish(pids)
	saveLiveAuditFixture(t, "adjacent-runtime.jsonl", runtime)
	manifest, _ := json.MarshalIndent(observed, "", "  ")
	saveLiveAuditFixture(t, "adjacent-observations.json", manifest)
	var selected bytes.Buffer
	counts := map[int64]int{}
	deadline := time.Now().Add(3 * time.Second)
	for {
		selected.Reset()
		counts = map[int64]int{}
		journal := liveAuditCommand(t, "journalctl", "-k", "--after-cursor", start.Cursor, "-n", "2000", "-o", "json", "--no-pager")
		scanner := bufio.NewScanner(bytes.NewReader(journal))
		scanner.Buffer(make([]byte, 4096), MaxAuditLineBytes)
		for scanner.Scan() {
			record, ok, err := ParseAuditLine(scanner.Bytes(), AuditSource{})
			if err != nil || !ok || record.Mechanism != "seccomp" || record.AuditPID == nil {
				continue
			}
			item, exists := observed[*record.AuditPID]
			if !exists {
				continue
			}
			if record.Decision != item.Decision || record.SyscallNumber == nil || *record.SyscallNumber != item.Syscall {
				t.Fatalf("unexpected journal decision: %+v", record)
			}
			counts[item.PID]++
			selected.Write(scanner.Bytes())
			selected.WriteByte('\n')
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	saveLiveAuditFixture(t, "adjacent-journal.jsonl", selected.Bytes())
	for pid, item := range observed {
		if counts[pid] != 1 {
			t.Fatalf("missing/duplicate real audit %s/%s pid=%d count=%d", item.Decision, item.Order, pid, counts[pid])
		}
	}
	db, _ := nativeTestStore(t)
	const run = "live-audit-adjacent"
	imported, err := IngestJSONLReader(db, JSONLIngestOptions{Format: "auto", RunID: run}, bytes.NewReader(runtime))
	if err != nil || imported.Failed != 0 || imported.Ingested == 0 {
		t.Fatalf("runtime import: %+v %v", imported, err)
	}
	if _, err := IngestAuditReader(context.Background(), db, AuditIngestOptions{RunID: run, RetainRaw: true}, bytes.NewReader(selected.Bytes())); err != nil {
		t.Fatal(err)
	}
	report, err := BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: run})
	if err != nil || len(report.Items) != len(observed) {
		t.Fatalf("associations: %+v %v", report, err)
	}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	saveLiveAuditFixture(t, "adjacent-associations.json", encoded)
	for _, item := range report.Items {
		if item.Process.Status != "inferred" || len(item.ProcessExits) == 0 {
			t.Fatalf("lifecycle evidence lost: %+v", item)
		}
		if item.Decision == "LOG" {
			if len(item.Operations) == 0 || item.Operation.Status != "inferred" && item.Operation.Status != "ambiguous" {
				t.Fatalf("LOG candidate lost: %+v", item)
			}
			continue
		}
		if item.Operation.Status != "unassociated" || len(item.Operations) != 0 || item.Operation.CandidateCount != 0 {
			t.Fatalf("rejected/mediated audit borrowed adjacent call: %+v", item)
		}
	}
	t.Log("14 real action/order cases; KILL deny-first terminates before second call; no rejected action borrowed adjacent results")
}

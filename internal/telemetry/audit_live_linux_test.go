package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

// This opt-in test creates only unattached, uniquely named fixture profiles.
// The production importer never loads a profile or changes the audit service.
func TestLiveAppArmorAuditImport(t *testing.T) {
	if os.Getenv("AGENTPROV_AUDIT_APPARMOR_LIVE") != "1" {
		t.Skip("set AGENTPROV_AUDIT_APPARMOR_LIVE=1 on a disposable Linux test host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("live AppArmor fixture requires root")
	}
	for _, tool := range []string{"cc", "apparmor_parser", "aa-exec", "journalctl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	probe, source, target := filepath.Join(dir, "probe"), filepath.Join(dir, "probe.c"), filepath.Join(dir, "fixture.secret")
	const program = `#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  char profile[512] = {0};
  FILE *f = fopen("/proc/self/attr/current", "r");
  if (!f || !fgets(profile, sizeof(profile), f)) return 3;
  fclose(f);
  for (int i = 0; profile[i]; ++i) if (profile[i] == '\n') profile[i] = 0;
  errno = 0;
  int result = open(argv[1], O_RDONLY), saved = errno;
  if (result >= 0) close(result);
  printf("{\"pid\":%d,\"result\":%d,\"errno\":%d,\"profile\":\"%s\"}\n", getpid(), result, saved, profile);
  return 0;
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("public acceptance fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	liveAuditCommand(t, "cc", "-static", "-O2", "-o", probe, source)
	var journalStart struct {
		Cursor string `json:"__CURSOR"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(liveAuditCommand(t, "journalctl", "-k", "-n", "1", "-o", "json", "--no-pager")), &journalStart); err != nil || journalStart.Cursor == "" {
		t.Fatalf("journal cursor unavailable: %v", err)
	}
	prefix := ids.New("agentprov-audit-fixture")
	profiles := fmt.Sprintf("profile %s-enforce {\n  %q rix,\n  /proc/** r,\n}\nprofile %s-complain flags=(complain) {\n  %q rix,\n  /proc/** r,\n}\n", prefix, probe, prefix, probe)
	policyPath := filepath.Join(dir, "profiles")
	if err := os.WriteFile(policyPath, []byte(profiles), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		liveAuditCommand(t, "apparmor_parser", "-K", "-R", policyPath)
		active, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
		if err != nil || bytes.Contains(active, []byte(prefix)) {
			t.Errorf("fixture profile cleanup failed: %v", err)
		}
	})
	liveAuditCommand(t, "apparmor_parser", "-K", "-a", policyPath)
	var finishSensor func([]int64) []byte
	if os.Getenv("AGENTPROV_AUDIT_SENSOR_LIVE") == "1" {
		finishSensor = startLiveAuditSensor(t)
	}
	type observation struct {
		PID     int64  `json:"pid"`
		Result  int    `json:"result"`
		Errno   int    `json:"errno"`
		Profile string `json:"profile"`
	}
	observations := map[string]observation{}
	for _, mode := range []string{"enforce", "complain"} {
		var result observation
		output := liveAuditCommand(t, "aa-exec", "-p", prefix+"-"+mode, "--", probe, target)
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("fixture result %q: %v", output, err)
		}
		if !strings.Contains(result.Profile, prefix+"-"+mode+" ("+mode+")") {
			t.Fatalf("actual profile state differs from fixture: %+v", result)
		}
		if mode == "enforce" && (result.Result != -1 || result.Errno != 13) {
			t.Fatalf("enforce did not deny fixture open: %+v", result)
		}
		if mode == "complain" && (result.Result < 0 || result.Errno != 0) {
			t.Fatalf("complain did not allow fixture open: %+v", result)
		}
		observations[mode] = result
	}
	var captured []byte
	if finishSensor != nil {
		captured = finishSensor([]int64{observations["enforce"].PID, observations["complain"].PID})
		saveLiveAuditFixture(t, "apparmor-runtime.jsonl", captured)
	}
	matched := map[string]AuditRecord{}
	var selected []string
	deadline := time.Now().Add(4 * time.Second)
	for {
		selected = nil
		matched = map[string]AuditRecord{}
		data := liveAuditCommand(t, "journalctl", "-k", "--after-cursor", journalStart.Cursor, "-n", "2000", "-o", "json", "--no-pager")
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), MaxAuditLineBytes)
		for scanner.Scan() {
			record, ok, err := ParseAuditLine(scanner.Bytes(), AuditSource{})
			if err != nil || !ok || record.Mechanism != "apparmor" || record.Target != target {
				continue
			}
			for mode, observed := range observations {
				if record.Profile == prefix+"-"+mode && record.AuditPID != nil && *record.AuditPID == observed.PID {
					matched[mode] = record
					selected = append(selected, scanner.Text())
				}
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		if len(matched) == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(matched) != 2 || matched["enforce"].Decision != "DENIED" || matched["complain"].Decision != "ALLOWED" {
		t.Fatalf("actual audit decisions missing: %+v", matched)
	}
	input := strings.Join(selected, "\n") + "\n"
	saveLiveAuditFixture(t, "apparmor-journal.jsonl", []byte(input))
	db, _ := nativeTestStore(t)
	opts := AuditIngestOptions{RunID: prefix, RetainRaw: true, Mechanism: "apparmor"}
	imported, err := IngestAuditReader(context.Background(), db, opts, strings.NewReader(input))
	if err != nil || imported.Ingested != 2 || imported.IdentityIncomplete != 0 {
		t.Fatalf("live import: %+v %v", imported, err)
	}
	repeated, err := IngestAuditReader(context.Background(), db, opts, strings.NewReader(input))
	if err != nil || repeated.Ingested != 0 || repeated.Duplicates != 2 {
		t.Fatalf("live duplicate import: %+v %v", repeated, err)
	}
	var associations AuditAssociationReport
	if len(captured) > 0 {
		scanner := bufio.NewScanner(bytes.NewReader(captured))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			var raw map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			event, ok, err := mapNative(raw)
			if err != nil || !ok {
				t.Fatalf("live native mapping failed: %v", err)
			}
			event.RunID = prefix
			if _, err := IngestFiltered(db, event); err != nil {
				t.Fatal(err)
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		associations, err = BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: prefix})
		debug, _ := json.MarshalIndent(associations, "", "  ")
		saveLiveAuditFixture(t, "apparmor-associations.json", debug)
		if err != nil || len(associations.Items) != 2 {
			t.Fatalf("live associations: %+v %v", associations, err)
		}
		for _, item := range associations.Items {
			if item.Process.Status != "inferred" || item.Operation.Status != "inferred" || len(item.Operations) != 1 || len(item.ProcessExits) == 0 {
				t.Fatalf("live process/operation not associated: %+v", item)
			}
			op := item.Operations[0]
			if op.AttemptState != "observed" || op.ResultState != "observed" || op.Result == nil {
				t.Fatalf("live attempt/result missing: %+v", op)
			}
			if item.Decision == "DENIED" && *op.Result != -13 || item.Decision == "ALLOWED" && *op.Result < 0 {
				t.Fatalf("sensor result disagrees with independent fixture: %+v", item)
			}
		}
	}
	if output := os.Getenv("AGENTPROV_AUDIT_EVIDENCE_DIR"); output != "" {
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		body, err := json.MarshalIndent(map[string]any{"fixture_profiles": profiles, "observations": observations, "audit_records": matched, "import": imported, "repeat": repeated, "associations": associations}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"apparmor.json": body, "apparmor-journal.jsonl": []byte(input), "apparmor-runtime.jsonl": captured} {
			if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("actual enforce=DENIED/EACCES; complain=ALLOWED/success; imported=%d duplicates=%d", imported.Ingested, repeated.Duplicates)
}

func saveLiveAuditFixture(t *testing.T, name string, data []byte) {
	t.Helper()
	if output := os.Getenv("AGENTPROV_AUDIT_EVIDENCE_DIR"); output != "" {
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

type auditCommandOutput struct{ bytes.Buffer }

func (b *auditCommandOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4<<20 {
		return 0, fmt.Errorf("live command output exceeds 4 MiB")
	}
	return b.Buffer.Write(p)
}

func liveAuditCommand(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, stderr auditCommandOutput
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v: %.2048s", name, err, stderr.String())
	}
	return out.Bytes()
}

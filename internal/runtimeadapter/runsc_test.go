//go:build linux || darwin

package runtimeadapter

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixture executes real subprocess/stdio/cancellation code after admission.
// Root-owned configuration checks are tested separately, without privileges.
func fakeRunsc(t *testing.T) Runsc {
	t.Helper()
	s := testRunsc()
	s.StateDir = t.TempDir()
	s.Config.Binary = filepath.Join(s.StateDir, "fake-runsc")
	code := `#!/bin/sh
pidfile=''
for arg in "$@"; do
  printf '<%s>' "$arg"
  case "$arg" in --internal-pid-file=*) pidfile=${arg#*=};; esac
  last=$arg
done
printf '\n'
case "$last" in
  missing) :;;
  malformed) printf '0\n' > "$pidfile";;
  *) printf '424242\n' > "$pidfile";;
esac
printf 'runtime stderr' >&2
case "$last" in
  failed) exit 7;;
  wait) exec /bin/sleep 30;;
  env) test -z "$AGENTPROV_TEST_SECRET" || exit 11;;
esac
exit 0
`
	if err := os.WriteFile(s.Config.Binary, []byte(code), 0o700); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRunscFixedEntryAndNativePIDChannel(t *testing.T) {
	s, r := fakeRunsc(t), testRequest()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	r.Command.Command, r.Command.Stdout, r.Command.Stderr = []string{"/bin/echo", "literal;not-shell", "env"}, stdout, stderr
	t.Setenv("AGENTPROV_TEST_SECRET", "must-not-inherit")
	starts := 0
	e, err := s.run(context.Background(), r, func(e Execution) error {
		starts++
		if e.SentryPID != 424242 || e.SentryPIDBasis != "runsc_internal_pid_file" {
			t.Error("running was reported without the runtime task PID")
		}
		return nil
	})
	if err != nil || e.State != "succeeded" || e.SentryPID != 424242 || e.SentryPIDBasis != "runsc_internal_pid_file" || starts != 1 {
		t.Fatalf("execution=%+v err=%v starts=%d", e, err, starts)
	}
	for _, arg := range []string{"<--root=/run/runsc><exec><--new-pidns>", "<--cwd=/workspace><container></bin/echo><literal;not-shell><env>"} {
		if !strings.Contains(stdout.String(), arg) {
			t.Fatalf("wrong runtime entry: %q", stdout.String())
		}
	}
	if stderr.String() != "runtime stderr" {
		t.Fatal(stderr.String())
	}
	if len(e.Gaps) != 3 || e.Record != nil {
		t.Fatalf("invented host capture or lost identity gaps: %+v", e)
	}
	entries, _ := os.ReadDir(s.StateDir)
	if len(entries) != 1 {
		t.Fatalf("PID scratch leaked: %v", entries)
	}
}

func TestRunscFailureAndMissingPIDRemainUnknown(t *testing.T) {
	for _, mode := range []string{"failed", "missing", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			s, r := fakeRunsc(t), testRequest()
			r.Command.Command = []string{mode}
			e, _ := s.run(context.Background(), r, nil)
			if e.State != "unknown" || e.ExitCode != nil || !e.Started {
				t.Fatalf("invented workload result: %+v", e)
			}
			if mode != "failed" && e.SentryPID != 0 {
				t.Fatal("borrowed the host launcher PID")
			}
		})
	}
}

func TestRunscCancellationTimeoutAndCheckpointFailure(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout", "checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			s, r := fakeRunsc(t), testRequest()
			r.Command.Command = []string{"wait"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.Options.Timeout = 20 * time.Millisecond
			before := time.Now()
			e, err := s.run(ctx, r, func(Execution) error {
				if mode == "cancel" {
					cancel()
				}
				if mode == "checkpoint" {
					return errors.New("checkpoint unavailable")
				}
				return nil
			})
			if time.Since(before) > 3*time.Second || err == nil || e.State != "unknown" || e.ExitCode != nil {
				t.Fatalf("cancellation did not reap transport: %+v %v", e, err)
			}
			if !strings.Contains(strings.Join(e.Gaps, ","), "workload_stop_unconfirmed") {
				t.Fatal(e.Gaps)
			}
		})
	}
}

func TestRunscStartFailureIsNotDispatched(t *testing.T) {
	s, r := fakeRunsc(t), testRequest()
	s.Config.Binary += "-missing"
	e, err := s.run(context.Background(), r, func(Execution) error { t.Fatal("not started"); return nil })
	if err == nil || e.Started || e.SentryPID != 0 {
		t.Fatalf("start failure: %+v %v", e, err)
	}
}

func TestTrustedRuntimePathsRejectCallerAndSymlink(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(file, []byte("{}"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTrustedFile(file, 64); err == nil {
		t.Fatal("accepted caller-writable configuration")
	}
	link := file + ".link"
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivatePID(link); err == nil {
		t.Fatal("accepted PID symlink")
	}
	if err := os.WriteFile(file, []byte("42"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readPrivatePID(file); err != nil || string(got) != "42" {
		t.Fatalf("owned PID: %q %v", got, err)
	}
}

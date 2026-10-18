//go:build linux

package accesscontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadProcfsSelf(t *testing.T) {
	s := ReadTask(os.Getpid(), os.Getpid(), Options{true, true})
	if err := ValidateSnapshot(s); err != nil {
		t.Fatal(err)
	}
	if s.Identity.Status != "observed" || s.Identity.StartTicks == "" {
		t.Fatalf("actual self state: %+v", s)
	}
	s = ReadTask(2147483647, 2147483647, Options{true, true})
	if s.Identity.Status != "unavailable" || s.Seccomp.Status == "observed" {
		t.Fatalf("gone task: %+v", s)
	}
}

func TestReadSourceIDIsBoundedAndValidated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	for _, tc := range []struct {
		input, want string
		uuid        bool
	}{
		{"ABCDEF0123456789ABCDEF0123456789\n", "abcdef0123456789abcdef0123456789", false},
		{"abcdef01-2345-6789-abcd-ef0123456789\n", "abcdef01-2345-6789-abcd-ef0123456789", true},
		{strings.Repeat("a", 300), "", false}, {strings.Repeat("0", 32), "", false},
		{"not-a-machine-id", "", false}, {strings.Repeat("a", 36), "", true},
	} {
		if err := os.WriteFile(path, []byte(tc.input), 0600); err != nil {
			t.Fatal(err)
		}
		if got := readSourceID(path, tc.uuid); got != tc.want {
			t.Fatalf("identity=%q want=%q", got, tc.want)
		}
	}
}

const stateProbe = `#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
static pthread_barrier_t barrier;
static long tids[2];
static void *worker(void *arg) {
  long n = (long)arg;
  if (n == 1) {
    struct sock_filter insn[] = {BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog filter = {1, insn};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)) _exit(3);
  }
  tids[n] = syscall(SYS_gettid);
  pthread_barrier_wait(&barrier);
  for (;;) pause();
  return 0;
}
int main(void) {
  pthread_t a,b;
  pthread_barrier_init(&barrier, 0, 3);
  if (pthread_create(&a,0,worker,(void*)0) || pthread_create(&b,0,worker,(void*)1)) return 2;
  pthread_barrier_wait(&barrier);
  printf("%d %ld %ld\n",getpid(),tids[0],tids[1]); fflush(stdout);
  char c; read(0,&c,1);
  return 0;
}
`

func TestLiveAccessStateProfilesAndThreads(t *testing.T) {
	if os.Getenv("AGENTPROV_ACCESS_STATE_LIVE") != "1" {
		t.Skip("set AGENTPROV_ACCESS_STATE_LIVE=1 on a disposable Linux host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("profile fixture requires root")
	}
	for _, tool := range []string{"cc", "apparmor_parser", "aa-exec"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	source, bin, policy := filepath.Join(dir, "probe.c"), filepath.Join(dir, "probe"), filepath.Join(dir, "profile")
	if err := os.WriteFile(source, []byte(stateProbe), 0600); err != nil {
		t.Fatal(err)
	}
	command := func(name string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
	}
	command("cc", "-static", "-O2", "-pthread", "-o", bin, source)
	prefix := fmt.Sprintf("agentprov-state-%d-%d", os.Getpid(), time.Now().UnixNano())
	text := fmt.Sprintf("profile %s-enforce { file, signal, ptrace, }\nprofile %s-complain flags=(complain) { file, signal, ptrace, }\n", prefix, prefix)
	if err := os.WriteFile(policy, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	command("apparmor_parser", "-K", "-a", policy)
	t.Cleanup(func() {
		command("apparmor_parser", "-K", "-R", policy)
		raw, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
		if err != nil || strings.Contains(string(raw), prefix) {
			t.Errorf("temporary profile cleanup: %v", err)
		}
	})
	var captured []Snapshot
	for _, mode := range []string{"enforce", "complain"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "aa-exec", "-p", prefix+"-"+mode, "--", bin)
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				in.Close()
				if err := cmd.Wait(); err != nil {
					t.Errorf("fixture exit: %v", err)
				}
			}()
			var pid, plain, filtered int
			if _, err := fmt.Fscanln(bufio.NewReader(out), &pid, &plain, &filtered); err != nil {
				t.Fatal(err)
			}
			a, b := ReadTask(pid, plain, Options{true, true}), ReadTask(pid, filtered, Options{true, true})
			for _, s := range []Snapshot{a, b} {
				if err := ValidateSnapshot(s); err != nil {
					t.Fatal(err)
				}
				if s.AppArmor.Mode != mode || !strings.Contains(s.AppArmor.Label, prefix+"-"+mode) || s.Identity.Status != "observed" {
					t.Fatalf("state=%+v", s)
				}
				captured = append(captured, s)
			}
			if a.Identity.TID == b.Identity.TID || b.Seccomp.Mode != "filter" || b.Seccomp.NoNewPrivs == nil || *b.Seccomp.NoNewPrivs != 1 || a.Seccomp.FilterCount == nil || b.Seccomp.FilterCount == nil || *b.Seccomp.FilterCount != *a.Seccomp.FilterCount+1 {
				t.Fatalf("thread-specific filter state collapsed: plain=%+v filtered=%+v", a, b)
			}
		})
	}
	if evidence := os.Getenv("AGENTPROV_ACCESS_STATE_EVIDENCE"); evidence != "" {
		if err := os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(captured, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(evidence, "task-states.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

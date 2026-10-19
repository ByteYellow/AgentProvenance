package accesscontrol

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

type fakeTask struct {
	files  map[string]string
	errors map[string]error
	reads  map[string]int
	after  map[string]string
}

func (f *fakeTask) read(path string) ([]byte, error) {
	f.reads[path]++
	if err := f.errors[path]; err != nil {
		return nil, err
	}
	if f.reads[path] > 1 {
		if value, ok := f.after[path]; ok {
			return []byte(value), nil
		}
	}
	value, ok := f.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(value), nil
}
func (f *fakeTask) link(string) (string, error)     { return "pid:[123]", nil }
func (f *fakeTask) cgroupID(string) (string, error) { return "567", nil }
func fakeStat(pid int, start string) string {
	return fmt.Sprintf("%d (name ) with spaces) S %s%s 0", pid, strings.Repeat("0 ", 18), start)
}
func taskFixture() *fakeTask {
	return &fakeTask{files: map[string]string{
		"stat": fakeStat(43, "12345"), "status": "Tgid:\t42\nPid:\t43\nSeccomp:\t2\nSeccomp_filters:\t1\nNoNewPrivs:\t0\n",
		"attr/apparmor/current": "test-profile (enforce)\n", "cgroup": "0::/scope\n",
	}, errors: map[string]error{}, reads: map[string]int{}, after: map[string]string{}}
}
func readFixture(f *fakeTask, opts Options) Snapshot { return readTask(f, newSnapshot(42, 43, opts)) }

func TestReadStateKeepsTaskSourceAndObservedZero(t *testing.T) {
	s := readFixture(taskFixture(), Options{true, true})
	if err := ValidateSnapshot(s); err != nil {
		t.Fatal(err)
	}
	if s.Identity.Status != "observed" || s.Identity.StartTicks != "12345" || s.Identity.CgroupID != "567" || s.Identity.PID != 42 || s.Identity.TID != 43 {
		t.Fatalf("identity=%+v", s.Identity)
	}
	if s.AppArmor.Label != "test-profile (enforce)" || s.AppArmor.Mode != "enforce" || s.Seccomp.Mode != "filter" || s.Seccomp.NoNewPrivs == nil || *s.Seccomp.NoNewPrivs != 0 {
		t.Fatalf("snapshot=%+v", s)
	}
}

func TestSeccompModesAreStateNotDecisions(t *testing.T) {
	for n, mode := range []string{"disabled", "strict", "filter"} {
		f := taskFixture()
		f.files["status"] = fmt.Sprintf("Tgid: 42\nPid: 43\nSeccomp: %d\nSeccomp_filters: 0\n", n)
		s := readFixture(f, Options{Seccomp: true})
		if s.Seccomp.Status != "observed" || s.Seccomp.Mode != mode || s.Seccomp.FilterCount == nil || *s.Seccomp.FilterCount != 0 || s.Seccomp.NoNewPrivs != nil || s.AppArmor.Status != "disabled" {
			t.Fatalf("snapshot=%+v", s)
		}
		if err := ValidateSnapshot(s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppArmorModeOnlyComesFromSpecificAttribute(t *testing.T) {
	for _, label := range []string{"unconfined", "profile (complain)", "profile (enforce)", "profile-without-mode", "a//&b (mixed)"} {
		f := taskFixture()
		f.files["attr/apparmor/current"] = label + "\n"
		s := readFixture(f, Options{AppArmor: true})
		if s.AppArmor.Label != label || s.AppArmor.Status != "observed" {
			t.Fatalf("label lost: %+v", s)
		}
		if label == "profile-without-mode" && s.AppArmor.Mode != "" {
			t.Fatal("guessed mode")
		}
	}
	f := taskFixture()
	delete(f.files, "attr/apparmor/current")
	f.files["attr/current"] = "selinux:label"
	s := readFixture(f, Options{AppArmor: true})
	if s.AppArmor.Status != "unavailable" || s.AppArmor.Reason != "not_present" || f.reads["attr/current"] != 0 {
		t.Fatalf("generic LSM label used: %+v", s)
	}
}

func TestStateFailuresRemainUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeTask)
	}{
		{"pid-reuse", func(f *fakeTask) { f.after["stat"] = fakeStat(43, "12346") }},
		{"wrong-thread", func(f *fakeTask) { f.files["status"] = "Tgid: 42\nPid: 44\nSeccomp: 2\n" }},
		{"duplicate-pid", func(f *fakeTask) { f.files["status"] += "Pid: 43\n" }},
		{"exit", func(f *fakeTask) { f.errors["stat"] = fs.ErrNotExist }},
		{"permission", func(f *fakeTask) { f.errors["status"] = fs.ErrPermission }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := taskFixture()
			tc.mutate(f)
			s := readFixture(f, Options{true, true})
			if s.Identity.Status != "unavailable" || s.AppArmor.Label != "" || s.Seccomp.ModeNumber != nil || s.Identity.CgroupID != "" {
				t.Fatalf("state survived identity failure: %+v", s)
			}
			if err := ValidateSnapshot(s); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, fields := range []string{"", "Seccomp: 3\n", "Seccomp: 2\nSeccomp: 2\n", "Seccomp: 2\nNoNewPrivs: 2\n", "Seccomp: 2\nSeccomp_filters: -1\n"} {
		f := taskFixture()
		f.files["status"] = "Tgid: 42\nPid: 43\n" + fields
		s := readFixture(f, Options{Seccomp: true})
		if s.Seccomp.Status == "observed" {
			t.Fatalf("invalid fields accepted: %+v", s)
		}
	}
	for _, err := range []error{fs.ErrPermission, errStateTooLarge} {
		f := taskFixture()
		f.errors["attr/apparmor/current"] = err
		s := readFixture(f, Options{true, true})
		if s.AppArmor.Status != "unavailable" || s.Seccomp.Status != "observed" {
			t.Fatalf("one source affected the other: %+v", s)
		}
	}
}

func TestCgroupMoveKeepsStateWithoutWorkloadAttribution(t *testing.T) {
	f := taskFixture()
	f.after["cgroup"] = "0::/other\n"
	s := readFixture(f, Options{true, true})
	if s.Identity.Status != "observed" || s.Identity.CgroupID != "" || s.Identity.CgroupReason != "cgroup_changed_or_unreadable" {
		t.Fatalf("unstable scope=%+v", s)
	}
}

func FuzzProcStateParsing(f *testing.F) {
	f.Add(fakeStat(43, "12345"), taskFixture().files["status"], "profile (enforce)")
	f.Fuzz(func(t *testing.T, stat, status, label string) {
		if len(stat)+len(status)+len(label) > 16384 {
			t.Skip()
		}
		input := taskFixture()
		input.files["stat"], input.files["status"], input.files["attr/apparmor/current"] = stat, status, label
		s := readFixture(input, Options{true, true})
		if err := ValidateSnapshot(s); err != nil {
			t.Fatal(err)
		}
	})
}

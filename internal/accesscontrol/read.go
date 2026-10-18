package accesscontrol

import (
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

type taskReader interface {
	read(string) ([]byte, error)
	link(string) (string, error)
	cgroupID(string) (string, error)
}

var errStateTooLarge = errors.New("procfs state exceeds size limit")

func readFailure(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission_denied"
	case errors.Is(err, fs.ErrNotExist):
		return "not_present"
	case errors.Is(err, errStateTooLarge):
		return "source_too_large"
	default:
		return "read_failed"
	}
}

func statIdentity(raw []byte) (int, string, bool) {
	start, end := strings.IndexByte(string(raw), '('), strings.LastIndexByte(string(raw), ')')
	if start < 1 || end <= start {
		return 0, "", false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw[:start])))
	fields := strings.Fields(string(raw[end+1:]))
	if err != nil || len(fields) < 20 {
		return 0, "", false
	}
	_, err = strconv.ParseUint(fields[19], 10, 64) // /proc stat field 22
	return pid, fields[19], err == nil
}

func statusFields(raw []byte) (map[string]string, bool) {
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch name {
		case "Pid", "Tgid", "Seccomp", "Seccomp_filters", "NoNewPrivs":
			if _, repeated := values[name]; repeated {
				return nil, false
			}
			values[name] = strings.TrimSpace(value)
		}
	}
	return values, true
}

func integerField(values map[string]string, key string, max int) (*int, bool) {
	raw, present := values[key]
	if !present {
		return nil, true
	}
	n, err := strconv.Atoi(raw)
	return &n, err == nil && n >= 0 && (max < 0 || n <= max)
}

func readTask(r taskReader, s Snapshot) Snapshot {
	finish := func() Snapshot { s.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano); return s }
	fail := func(reason string) Snapshot {
		s.Identity.Status, s.Identity.Reason = "unavailable", reason
		s.Identity.StartTicks, s.Identity.CgroupID, s.Identity.CgroupPath = "", "", ""
		for _, state := range []*State{&s.AppArmor, &s.Seccomp} {
			if state.Status != "disabled" {
				*state = State{Status: "unavailable", Reason: reason}
			}
		}
		return finish()
	}
	before, err := r.read("stat")
	if err != nil {
		return fail(readFailure(err))
	}
	pid, ticks, valid := statIdentity(before)
	if !valid || pid != s.Identity.TID {
		return fail("task_identity_mismatch")
	}
	raw, err := r.read("status")
	if err != nil {
		return fail(readFailure(err))
	}
	values, valid := statusFields(raw)
	if !valid || values["Tgid"] != strconv.Itoa(s.Identity.PID) || values["Pid"] != strconv.Itoa(s.Identity.TID) {
		return fail("task_identity_mismatch")
	}
	s.Identity.Status, s.Identity.StartTicks = "observed", ticks
	s.Identity.PIDNamespace, _ = r.link("ns/pid")
	if s.Seccomp.Status != "disabled" {
		mode, modeOK := integerField(values, "Seccomp", 2)
		filters, filtersOK := integerField(values, "Seccomp_filters", -1)
		nnp, nnpOK := integerField(values, "NoNewPrivs", 1)
		s.Seccomp = State{Status: "unavailable", Source: "status", Reason: "seccomp_field_missing"}
		if !modeOK || !filtersOK || !nnpOK {
			s.Seccomp.Reason = "invalid_status_fields"
		} else if mode != nil {
			s.Seccomp = State{Status: "observed", Source: "status", ModeNumber: mode,
				Mode: []string{"disabled", "strict", "filter"}[*mode], FilterCount: filters, NoNewPrivs: nnp}
		}
	}
	if s.AppArmor.Status != "disabled" {
		const source = "attr/apparmor/current"
		raw, err := r.read(source)
		s.AppArmor = State{Status: "unavailable", Source: source}
		if err != nil {
			s.AppArmor.Reason = readFailure(err)
		} else {
			label := strings.TrimSuffix(string(raw), "\n")
			if label == "" || strings.ContainsAny(label, "\x00\n\r") || len(label) > 8192 {
				s.AppArmor.Reason = "invalid_apparmor_label"
			} else {
				s.AppArmor.Status, s.AppArmor.Label = "observed", label
				if label == "unconfined" {
					s.AppArmor.Mode = "unconfined"
				} else {
					for _, mode := range []string{"enforce", "complain", "kill", "unconfined", "mixed"} {
						if strings.HasSuffix(label, " ("+mode+")") {
							s.AppArmor.Mode = mode
							break
						}
					}
				}
			}
		}
	}
	// Membership is sampled independently. Moving cgroups during the read leaves
	// the snapshot readable but prevents attaching an unstable workload scope.
	cgroup, cgroupErr := r.read("cgroup")
	s.Identity.CgroupReason = "cgroup_v2_unresolved"
	if cgroupErr == nil {
		for _, line := range strings.Split(string(cgroup), "\n") {
			if path, ok := strings.CutPrefix(line, "0::"); ok && strings.HasPrefix(path, "/") && len(path) <= 4096 {
				s.Identity.CgroupPath = path
				s.Identity.CgroupID, err = r.cgroupID(path)
				if err == nil {
					s.Identity.CgroupReason = ""
				}
				break
			}
		}
	}
	after, err := r.read("stat")
	if err != nil {
		return fail(readFailure(err))
	}
	afterPID, afterTicks, valid := statIdentity(after)
	if !valid || afterPID != pid || afterTicks != ticks {
		return fail("task_changed_during_read")
	}
	latest, err := r.read("cgroup")
	if err != nil || string(latest) != string(cgroup) {
		s.Identity.CgroupID, s.Identity.CgroupReason = "", "cgroup_changed_or_unreadable"
	}
	return finish()
}

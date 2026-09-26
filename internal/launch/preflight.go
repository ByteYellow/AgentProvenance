package launch

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// CheckStatus is the operator-facing state of one launch preflight check.
type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
	CheckSkip CheckStatus = "skip"
)

// Check is one launch prerequisite or degradation check.
type Check struct {
	detail message
	fix    message
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
	Fix    string      `json:"fix,omitempty"`
}

// PreflightReport is the structured launch readiness report.
type PreflightReport struct {
	Command       []string `json:"command,omitempty"`
	SelfExe       string   `json:"self_exe,omitempty"`
	DashboardAddr string   `json:"dashboard_addr,omitempty"`
	SensorMode    string   `json:"sensor_mode,omitempty"`
	Checks        []Check  `json:"checks"`
}

// Preflight inspects whether launch can observe the requested command before it
// starts long-lived children. It is intentionally side-effect-light: the only
// filesystem probe creates and removes a temporary cgroup leaf when Linux cgroup
// v2 appears writable, matching the operation record will need later.
func Preflight(opts Options) PreflightReport {
	if opts.SelfExe == "" {
		if exe, err := os.Executable(); err == nil {
			opts.SelfExe = exe
		}
	}
	if opts.DashboardAddr == "" {
		opts.DashboardAddr = "127.0.0.1:7396"
	}
	if opts.Sensor == "" {
		opts.Sensor = "auto"
	}
	r := PreflightReport{
		Command:       append([]string(nil), opts.Command...),
		SelfExe:       opts.SelfExe,
		DashboardAddr: opts.DashboardAddr,
		SensorMode:    opts.Sensor,
	}
	r.Checks = append(r.Checks, checkCommand(opts.Command))
	r.Checks = append(r.Checks, checkClaudeHooks(opts.Command))
	r.Checks = append(r.Checks, checkDashboardAddr(opts.Dashboard, opts.DashboardAddr))
	r.Checks = append(r.Checks, checkCgroup())
	r.Checks = append(r.Checks, checkSensor(opts.Sensor, opts.SelfExe))
	return r
}

func (r PreflightReport) HasFailures() bool {
	for _, c := range r.Checks {
		if c.Status == CheckFail {
			return true
		}
	}
	return false
}

func checkCommand(command []string) Check {
	if len(command) == 0 {
		return makeCheck("agent command", CheckSkip, messagef("no command supplied; pass one after -- to check the agent binary"))
	}
	prog := command[0]
	if strings.ContainsRune(prog, os.PathSeparator) {
		info, err := os.Stat(prog)
		if err != nil {
			return makeCheck("agent command", CheckFail, messagef("%s is not accessible", prog), messagef("%s", err))
		}
		if info.IsDir() || info.Mode()&0o111 == 0 {
			return makeCheck("agent command", CheckFail, messagef("%s is not executable", prog))
		}
		return makeCheck("agent command", CheckPass, messagef("%s is executable", prog))
	}
	path, err := exec.LookPath(prog)
	if err != nil {
		return makeCheck("agent command", CheckFail, messagef("%s not found on PATH", prog), messagef("install it or pass an absolute path"))
	}
	return makeCheck("agent command", CheckPass, messagef("%s", path))
}

func checkClaudeHooks(command []string) Check {
	if len(command) == 0 {
		return makeCheck("Claude hooks", CheckSkip, messagef("no agent command supplied"))
	}
	recipe := detectRecipe(command)
	if !recipe.injectHooks {
		return makeCheck("Claude hooks", CheckSkip, recipe.detailText)
	}
	for _, a := range command[1:] {
		if a == "--settings" || strings.HasPrefix(a, "--settings=") {
			return makeCheck("Claude hooks", CheckWarn, messagef("command already passes --settings, so launch will not override it"), messagef("remove --settings for per-run hook capture, or run record-only intentionally"))
		}
	}
	return makeCheck("Claude hooks", CheckPass, recipe.detailText)
}

func checkDashboardAddr(enabled bool, addr string) Check {
	if !enabled {
		return makeCheck("dashboard port", CheckSkip, messagef("dashboard disabled"))
	}
	if addr == "" {
		addr = "127.0.0.1:7396"
	}
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		_ = ln.Close()
		return makeCheck("dashboard port", CheckPass, messagef("%s is available", addr))
	}
	return makeCheck("dashboard port", CheckWarn, messagef("%s is not available; launch will fall back to an ephemeral port", addr), messagef("%s", err))
}

func checkCgroup() Check {
	if runtime.GOOS != "linux" {
		return makeCheck("cgroup v2", CheckSkip, messagef("not available on %s; record uses a logical scope id", runtime.GOOS))
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return makeCheck("cgroup v2", CheckWarn, messagef("unified cgroup v2 not detected; kernel correlation falls back to pid/time"), messagef("%s", err))
	}
	parent := firstNonEmpty(os.Getenv("AGENTPROV_CGROUP_PARENT"), "/sys/fs/cgroup/agentprov")
	dir := filepath.Join(parent, ".agentprov-preflight-"+strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return makeCheck("cgroup v2", CheckWarn, messagef("%s is not writable/delegated; record will use synthetic cgroup ids", parent), messagef("create and delegate AGENTPROV_CGROUP_PARENT, or run with sufficient cgroup privileges: %s", err))
	}
	_ = os.Remove(dir)
	return makeCheck("cgroup v2", CheckPass, messagef("%s can host per-run scopes", parent))
}

func checkSensor(mode, selfExe string) Check {
	if mode == "off" {
		return makeCheck("kernel sensor", CheckSkip, messagef("disabled via --sensor=off"))
	}
	if runtime.GOOS != "linux" {
		return makeCheck("kernel sensor", CheckSkip, messagef("requires Linux; this host is %s", runtime.GOOS))
	}
	if selfExe == "" {
		return makeCheck("kernel sensor", CheckWarn, messagef("cannot locate agentprov binary for sensor subprocess"))
	}
	if _, err := os.Stat(selfExe); err != nil {
		return makeCheck("kernel sensor", CheckWarn, messagef("agentprov binary is not accessible"), messagef("%s", err))
	}
	if os.Geteuid() == 0 || hasEffectiveCap(38) && hasEffectiveCap(39) {
		return makeCheck("kernel sensor", CheckPass, messagef("Linux host has root or CAP_PERFMON+CAP_BPF"))
	}
	return makeCheck("kernel sensor", CheckWarn, messagef("Linux host lacks root/CAP_PERFMON+CAP_BPF; launch will degrade to app/record evidence"), messagef("run as root or grant capabilities to the agentprov binary (for example: sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep %s)", selfExe))
}

func hasEffectiveCap(bit uint) bool {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return false
			}
			v, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return false
			}
			return v&(uint64(1)<<bit) != 0
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

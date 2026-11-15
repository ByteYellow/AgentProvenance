package launch

import (
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
)

const supportedFirecracker = "v1.18.0"

type RuntimePreflightOptions struct {
	Runtime string
	Binary  string
	Rootfs  string
	Kernel  string
}

// RuntimePreflight checks local prerequisites without creating a container,
// virtual machine, network device or evidence store.
func RuntimePreflight(opts RuntimePreflightOptions) []Check {
	if opts.Runtime == "" {
		if opts.Binary != "" || opts.Rootfs != "" || opts.Kernel != "" {
			return []Check{makeCheck("runtime selection", CheckFail, messagef("runtime artifact paths require a runtime selection"), messagef("Set --runtime runsc or --runtime firecracker"))}
		}
		return nil
	}
	if opts.Runtime != "runsc" && opts.Runtime != "firecracker" {
		return []Check{makeCheck("runtime selection", CheckFail, messagef("unsupported runtime"), messagef("Use --runtime runsc or --runtime firecracker"))}
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return []Check{makeCheck("runtime host", CheckFail, messagef("this runtime requires Linux amd64 or arm64"), messagef("Run this check on the intended Linux runtime host"))}
	}
	binary := opts.Binary
	if binary == "" {
		binary = opts.Runtime
	}
	want := seccheck.RuntimeRelease
	if opts.Runtime == "firecracker" {
		want = supportedFirecracker
	}
	checks := []Check{checkRuntimeBinary(binary, want)}
	checks = append(checks, checkRuntimeFile("runtime rootfs", opts.Rootfs, opts.Runtime == "runsc", "--runtime-rootfs"))
	if opts.Runtime == "firecracker" {
		checks = append(checks, checkRuntimeFile("runtime kernel", opts.Kernel, false, "--runtime-kernel"))
		for _, device := range []string{"/dev/kvm", "/dev/net/tun"} {
			status := CheckPass
			info, err := os.Stat(device)
			if err != nil || info.Mode()&os.ModeCharDevice == 0 {
				status = CheckFail
			} else if f, err := os.OpenFile(device, os.O_RDWR, 0); err != nil {
				status = CheckFail
			} else {
				_ = f.Close()
			}
			if status == CheckFail {
				checks = append(checks, makeCheck("runtime "+device, status, messagef("required device is unavailable or not writable"), messagef("Enable the host device and grant the runtime user access to %s", device)))
			} else {
				checks = append(checks, makeCheck("runtime "+device, status, messagef("character device is accessible for read/write")))
			}
		}
		for _, command := range []string{"ip", "dnsmasq", "ssh", "mkfs.ext4"} {
			if _, err := exec.LookPath(command); err != nil {
				checks = append(checks, makeCheck("runtime helper "+command, CheckFail, messagef("guest acceptance helper is missing"), messagef("Install %s on the runtime host", command)))
			} else {
				checks = append(checks, makeCheck("runtime helper "+command, CheckPass, messagef("guest acceptance helper is available")))
			}
		}
	}
	if os.Geteuid() != 0 {
		checks = append(checks, makeCheck("runtime permissions", CheckWarn, messagef("the documented runtime acceptance uses root privileges"), messagef("Repeat doctor as the account that will run the acceptance; keep the current result for comparison")))
	}
	return checks
}

type preflightVersionOutput struct{ data []byte }

func (b *preflightVersionOutput) Write(p []byte) (int, error) {
	n := len(p)
	if room := 8192 - len(b.data); room > 0 {
		b.data = append(b.data, p[:min(room, n)]...)
	}
	return n, nil
}

func checkRuntimeBinary(binary, want string) Check {
	path, err := exec.LookPath(binary)
	if err != nil {
		return makeCheck("runtime binary", CheckFail, messagef("runtime executable is unavailable"), messagef("Install the pinned runtime or set --runtime-binary to its executable"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	var out preflightVersionOutput
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if err := cmd.Run(); err != nil {
		return makeCheck("runtime binary", CheckFail, messagef("runtime version check failed"), messagef("Check executable permissions and architecture for --runtime-binary"))
	}
	found := false
	for _, field := range strings.Fields(string(out.data)) {
		if field == want {
			found = true
		}
	}
	if !found {
		return makeCheck("runtime version", CheckFail, messagef("runtime does not report the supported release %s", want), messagef("Install the pinned runtime before acceptance"))
	}
	return makeCheck("runtime version", CheckPass, messagef("runtime reports %s", want))
}

func checkRuntimeFile(name, path string, directory bool, flag string) Check {
	if path == "" {
		return makeCheck(name, CheckWarn, messagef("no path supplied for this check"), messagef("Set %s to check the selected artifact", flag))
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() != directory || !directory && !info.Mode().IsRegular() {
		return makeCheck(name, CheckFail, messagef("selected artifact is missing or has the wrong file type"), messagef("Check %s", flag))
	}
	f, err := os.Open(path)
	if err != nil {
		return makeCheck(name, CheckFail, messagef("selected artifact is not readable"), messagef("Check permissions for %s", flag))
	}
	_ = f.Close()
	return makeCheck(name, CheckPass, messagef("selected artifact exists and is readable"))
}

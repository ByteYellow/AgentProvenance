package handoff

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
)

func runtimeConfig() Config {
	c := Config{Target: Target{"producer", "instance", "generation"}, Concurrency: 1,
		Backend: &BackendConfig{Mode: "runsc", Runsc: &runtimeadapter.RunscConfig{Binary: "/usr/local/bin/runsc", Root: "/run/runsc", ContainerID: "container",
			StateCreated: "2026-11-16T00:00:00Z", RuntimeRelease: seccheck.RuntimeRelease, Workdir: "/workspace", AllowUncorrelated: true}}}
	c.Caller.PrincipalID, c.Caller.ProducerID, c.Caller.Namespace = "router", "source", "namespace"
	c.Backend.SecCheck = &SecCheckConfig{StatusFile: "/run/agentprov/receiver.jsonl", Target: seccheck.Target{RunID: "container-run", SocketPath: "/run/agentprov/events.sock",
		Registration: seccheck.Registration{Namespace: "producer", InstanceID: "instance", Generation: "generation", SandboxID: "sandbox", ContainerID: "container", PeerUID: 0}}}
	return c
}

func TestRuntimeConfigRoundTripAndRejection(t *testing.T) {
	c := runtimeConfig()
	raw, _ := json.Marshal(c)
	if _, err := ReadConfig(strings.NewReader(string(raw))); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"concurrency", "native_capture", "version", "gap_policy", "generation", "producer", "instance", "container", "peer", "relative_status", "unknown_backend"} {
		t.Run(mode, func(t *testing.T) {
			c := runtimeConfig()
			switch mode {
			case "concurrency":
				c.Concurrency = 2
			case "native_capture":
				c.Capture = &CaptureConfig{Mode: "native"}
			case "version":
				c.Backend.Runsc.RuntimeRelease = "latest"
			case "gap_policy":
				c.Backend.Runsc.AllowUncorrelated = false
			case "generation":
				c.Backend.SecCheck.Target.Registration.Generation = "old"
			case "producer":
				c.Backend.SecCheck.Target.Registration.Namespace = "foreign"
			case "instance":
				c.Backend.SecCheck.Target.Registration.InstanceID = "clone"
			case "container":
				c.Backend.SecCheck.Target.Registration.ContainerID = "other"
			case "peer":
				c.Backend.SecCheck.Target.Registration.PeerUID = 1000
			case "relative_status":
				c.Backend.SecCheck.StatusFile = "status.jsonl"
			case "unknown_backend":
				c.Backend.Mode = "kata-auto"
			}
			raw, _ := json.Marshal(c)
			if _, err := ReadConfig(strings.NewReader(string(raw))); err == nil {
				t.Fatal("accepted invalid runtime configuration")
			}
		})
	}
}

func TestNativeAndGuestBackendConfiguration(t *testing.T) {
	for _, mode := range []string{"", "native", "guest"} {
		c := runtimeConfig()
		c.Backend = nil
		c.Concurrency = 2
		if mode != "" {
			c.Backend = &BackendConfig{Mode: mode}
		}
		if mode == "guest" {
			c.Capture = &CaptureConfig{Mode: "native", Placement: "guest_kernel"}
		}
		raw, _ := json.Marshal(c)
		got, err := ReadConfig(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		if got.Concurrency != 2 {
			t.Fatal("native concurrency default changed")
		}
		if mode == "guest" {
			c.Capture.Placement = "host_kernel"
			raw, _ = json.Marshal(c)
			if _, err := ReadConfig(strings.NewReader(string(raw))); err == nil {
				t.Fatal("guest selected host collector")
			}
		}
	}
}

func TestGuestMetadataConfigurationRequiresCompleteMapping(t *testing.T) {
	c := runtimeConfig()
	c.Backend = &BackendConfig{Mode: "guest", Guest: &runtimeadapter.GuestIdentity{RuntimeClass: "kata-qemu", RuntimeHandler: "kata-qemu-runtime-rs", PodUID: "pod", ContainerID: "container", GuestBootID: "boot"}}
	c.Capture = &CaptureConfig{Mode: "native", Placement: "guest_kernel"}
	raw, _ := json.Marshal(c)
	if _, err := ReadConfig(strings.NewReader(string(raw))); err != nil {
		t.Fatal(err)
	}
	c.Backend.Guest.PodUID = ""
	raw, _ = json.Marshal(c)
	if _, err := ReadConfig(strings.NewReader(string(raw))); err == nil {
		t.Fatal("accepted partial guest mapping")
	}
}

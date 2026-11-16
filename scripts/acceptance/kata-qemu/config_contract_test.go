package kataqemu_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
)

// Exercise the fixture generator against the production decoder, not a copied schema.
func fixtureConfig(t *testing.T) ([]byte, handoff.Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-B", "-c", `import json
from binding import configuration
print(json.dumps(configuration(
    {"producer_id":"kata-acceptance-fixture","instance_id":"pod-1","generation":"operator-generation-1"},
    {"runtime_class":"kata-qemu-runtime-rs","runtime_handler":"kata-qemu-runtime-rs",
     "pod_uid":"pod-1","container_id":"a"*64,"guest_boot_id":"a4e66e5f-d280-4d9d-ae8f-7c88d710efb6"})))`)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := handoff.ReadConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("generated configuration rejected: %v", err)
	}
	return raw, cfg
}

func TestGeneratedGuestConfigUsesProductionBinding(t *testing.T) {
	_, cfg := fixtureConfig(t)
	if cfg.Backend == nil || cfg.Backend.Mode != "guest" || cfg.Backend.Guest == nil ||
		cfg.Capture == nil || cfg.Capture.Mode != "native" || cfg.Capture.Placement != "guest_kernel" {
		t.Fatalf("fixture did not configure the actual Guest backend: %+v", cfg)
	}
	target := runtimeadapter.Target(cfg.Target)
	identity := *cfg.Backend.Guest
	binding := (runtimeadapter.Binding{Target: target, Mode: "guest"}).WithGuest(identity)
	if err := binding.ValidateGuest(target, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Resolve(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*runtimeadapter.GuestIdentity){
		"pod":       func(g *runtimeadapter.GuestIdentity) { g.PodUID = "different-pod" },
		"container": func(g *runtimeadapter.GuestIdentity) { g.ContainerID = "different-container" },
		"boot":      func(g *runtimeadapter.GuestIdentity) { g.GuestBootID = "different-boot" },
		"class":     func(g *runtimeadapter.GuestIdentity) { g.RuntimeClass = "different-class" },
		"handler":   func(g *runtimeadapter.GuestIdentity) { g.RuntimeHandler = "different-handler" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := identity
			mutate(&changed)
			if binding.ValidateGuest(target, changed) == nil {
				t.Fatal("mismatched native identity accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*runtimeadapter.Target){
		"producer":   func(g *runtimeadapter.Target) { g.ProducerID += "-other" },
		"instance":   func(g *runtimeadapter.Target) { g.InstanceID += "-other" },
		"generation": func(g *runtimeadapter.Target) { g.Generation += "-other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := target
			mutate(&changed)
			if binding.ValidateGuest(changed, identity) == nil {
				t.Fatal("mismatched Target accepted")
			}
			if _, err := binding.Resolve(context.Background(), changed); err == nil {
				t.Fatal("mismatched Target resolved")
			}
		})
	}
}

func TestGeneratedConfigRejectsIncompleteGuestMapping(t *testing.T) {
	raw, _ := fixtureConfig(t)
	for _, key := range []string{"runtime_class", "runtime_handler", "pod_uid", "container_id", "guest_boot_id"} {
		t.Run(key, func(t *testing.T) {
			var cfg map[string]any
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			delete(cfg["backend"].(map[string]any)["guest"].(map[string]any), key)
			changed, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := handoff.ReadConfig(bytes.NewReader(changed)); err == nil {
				t.Fatal("incomplete Guest identity accepted")
			}
		})
	}
}

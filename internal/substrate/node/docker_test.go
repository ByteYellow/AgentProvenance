package node

import (
	"testing"

	"github.com/docker/docker/api/types/mount"
)

func TestBuildHostConfigDropsAllCapabilities(t *testing.T) {
	req := CreateSessionRequest{WorkspaceHostPath: "/tmp/ap-data/workspaces/sbx-x"}
	cfg := buildHostConfig(req)

	if len(cfg.CapDrop) != 1 || cfg.CapDrop[0] != "ALL" {
		t.Fatalf("CapDrop = %v, want [ALL]", cfg.CapDrop)
	}
	hasNoNewPrivs := false
	for _, opt := range cfg.SecurityOpt {
		if opt == "no-new-privileges" {
			hasNoNewPrivs = true
		}
	}
	if !hasNoNewPrivs {
		t.Fatalf("SecurityOpt = %v, want to contain no-new-privileges", cfg.SecurityOpt)
	}
}

func TestBuildHostConfigKeepsWorkspaceBindMount(t *testing.T) {
	req := CreateSessionRequest{WorkspaceHostPath: "/tmp/ws"}
	cfg := buildHostConfig(req)

	if len(cfg.Mounts) != 1 {
		t.Fatalf("Mounts = %v, want exactly one workspace bind", cfg.Mounts)
	}
	m := cfg.Mounts[0]
	if m.Type != mount.TypeBind || m.Source != "/tmp/ws" || m.Target != "/workspace" {
		t.Fatalf("unexpected mount: %+v", m)
	}
	if m.ReadOnly {
		t.Fatalf("workspace bind must stay read-write for session function")
	}
}

func TestBuildHostConfigPreservesOptionalSettings(t *testing.T) {
	req := CreateSessionRequest{
		WorkspaceHostPath: "/tmp/ws",
		DockerNetworkName: "ap-net",
		MemoryMB:          256,
	}
	cfg := buildHostConfig(req)

	if string(cfg.NetworkMode) != "ap-net" {
		t.Fatalf("NetworkMode = %q, want ap-net", cfg.NetworkMode)
	}
	if cfg.Resources.Memory != 256*1024*1024 {
		t.Fatalf("Memory = %d, want %d", cfg.Resources.Memory, 256*1024*1024)
	}

	plain := buildHostConfig(CreateSessionRequest{WorkspaceHostPath: "/tmp/ws"})
	if plain.NetworkMode != "" || plain.Resources.Memory != 0 {
		t.Fatalf("defaults must not set network/memory, got %+v", plain)
	}
	if len(plain.CapDrop) != 1 || plain.CapDrop[0] != "ALL" || len(plain.SecurityOpt) == 0 {
		t.Fatalf("defaults must keep hardening, got %+v", plain)
	}
}

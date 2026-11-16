package runtimeadapter

import (
	"context"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
)

func testRequest() Request {
	return Request{Target: Target{"producer", "instance", "generation"}, OperationID: "operation", AttemptID: "attempt",
		Command: record.Request{RunID: "run", Command: []string{"/bin/true"}, DisableSnapshot: true}}
}

func testRunsc() Runsc {
	r := testRequest()
	c := RunscConfig{Binary: "/usr/local/bin/runsc", Root: "/run/runsc", ContainerID: "container", StateCreated: "2026-11-16T00:00:00Z",
		RuntimeRelease: seccheck.RuntimeRelease, Workdir: "/workspace", AllowUncorrelated: true}
	return Runsc{Binding: Binding{Target: r.Target, Mode: "runsc", ContainerID: c.ContainerID, StateCreated: c.StateCreated}, Config: c, StateDir: "/run/agentprov"}
}

func TestPlatformBindingRejectsEveryTargetComponent(t *testing.T) {
	r := testRequest()
	b := Binding{Target: r.Target, Mode: "native"}
	for _, target := range []Target{{"foreign", "instance", "generation"}, {"producer", "foreign", "generation"}, {"producer", "instance", "restored"}} {
		if _, err := b.Resolve(context.Background(), target); err == nil {
			t.Fatalf("accepted foreign target: %+v", target)
		}
	}
	if _, err := b.Resolve(context.Background(), r.Target); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Resolve(ctx, r.Target); err == nil {
		t.Fatal("accepted cancelled binding resolution")
	}
}

func TestNativeAdapterPreservesProtocolIdentityAlphabet(t *testing.T) {
	r := testRequest()
	r.OperationID = "operation/with:separators"
	r.Target.Generation = strings.Repeat("a", 512)
	n := Native{Binding: Binding{Target: r.Target, Mode: "native"}}
	if err := n.Admit(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Target.Generation += "a"
	if err := n.Admit(context.Background(), r); err == nil {
		t.Fatal("accepted invalid native identity")
	}
}

func TestRunscAdmissionRejectsUnsupportedGuarantees(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*Runsc, *Request)
	}{
		{"generation", "mismatch", func(s *Runsc, r *Request) { r.Target.Generation = "old" }},
		{"capture guarantee", "allow_uncorrelated", func(s *Runsc, r *Request) { s.Config.AllowUncorrelated = false }},
		{"version", "pinned runtime", func(s *Runsc, r *Request) { s.Config.RuntimeRelease = "unpinned" }},
		{"snapshot", "disable_snapshot", func(s *Runsc, r *Request) { r.Command.DisableSnapshot = false }},
		{"workdir", "configured container workdir", func(s *Runsc, r *Request) { r.Command.Workdir = "/workspace/subdir" }},
		{"shell", "shell interpreter", func(s *Runsc, r *Request) { r.Command.Command = []string{"/bin/sh", "-c", "true"} }},
		{"environment", "inherited host environment", func(s *Runsc, r *Request) { s.Options.InheritFullEnv = true }},
		{"container", "binding mismatch", func(s *Runsc, r *Request) { s.Binding.ContainerID = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r := testRunsc(), testRequest()
			tc.change(&s, &r)
			if err := s.Admit(context.Background(), r); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v; want %s", err, tc.want)
			}
		})
	}
}

func TestRunscRuntimeLifecycleFence(t *testing.T) {
	s := testRunsc()
	// Exact OCI output shape observed from the pinned runtime, with no created field.
	if err := s.validateState([]byte(`{"ociVersion":"1.2.1","id":"container","status":"running","pid":2767,"bundle":"/root/fixture"}`)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"id":"container","status":"running","pid":0}`,
		`{"id":"container","status":"stopped","pid":2767}`,
		`{"id":"reused","status":"running","pid":2767}`,
		`{"id":"container","status":"running"}`,
	} {
		if err := s.validateState([]byte(raw)); err == nil {
			t.Fatalf("accepted lifecycle mismatch: %s", raw)
		}
	}
}

func TestRunscLifecycleUsesPinnedRuntimeMetadata(t *testing.T) {
	good := `{"id":"container","createdAt":"2026-11-16T00:00:00.123456789Z","sandbox":{"id":"sandbox"},"spec":{"process":{"env":["PRIVATE=fixture"]}}}`
	lifecycle, err := decodeRunscLifecycle([]byte(good), "container", "container_sandbox:sandbox.state")
	if err != nil || lifecycle.CreatedAt != "2026-11-16T00:00:00.123456789Z" {
		t.Fatalf("runtime creation identity: %+v %v", lifecycle, err)
	}
	for _, raw := range []string{
		strings.Replace(good, `"id":"container"`, `"id":"other"`, 1),
		strings.Replace(good, `"id":"sandbox"`, `"id":"../sandbox"`, 1),
		strings.Replace(good, `"createdAt"`, `"created"`, 1),
		strings.Replace(good, "2026-11-16T00:00:00.123456789Z", "invalid", 1),
	} {
		if _, err := decodeRunscLifecycle([]byte(raw), "container", "container_sandbox:sandbox.state"); err == nil {
			t.Fatal("accepted invalid lifecycle metadata")
		}
	}
	if _, err := decodeRunscLifecycle([]byte(good), "container", "container_sandbox:other.state"); err == nil {
		t.Fatal("accepted lifecycle metadata from a different sandbox")
	}
}

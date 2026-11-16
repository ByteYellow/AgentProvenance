//go:build linux

package runtimeadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"google.golang.org/protobuf/encoding/protojson"
)

// This opt-in acceptance uses a new disposable container and a separate
// receiver. Artifacts retain exact protobuf identity fields, not credentials,
// argv or environment. Matching PID samples are candidates, not call edges.
func TestRunscLiveExecutionIdentityEvidence(t *testing.T) {
	binary, rootfs, out := os.Getenv("AGENTPROV_TEST_RUNSC"), os.Getenv("AGENTPROV_TEST_GVISOR_ROOTFS"), os.Getenv("AGENTPROV_TEST_RUNTIME_ADAPTER_OUTPUT")
	if binary == "" || rootfs == "" || out == "" {
		t.Skip("set AGENTPROV_TEST_RUNSC, AGENTPROV_TEST_GVISOR_ROOTFS and AGENTPROV_TEST_RUNTIME_ADAPTER_OUTPUT")
	}
	if os.Geteuid() != 0 {
		t.Fatal("runsc acceptance requires root")
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrustedPath(out, true); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(out, "run-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime adapter evidence: %s", root)
	writeJSON := func(name string, value any) {
		t.Helper()
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	container := "agentprov-adapter-test"
	target := Target{"acceptance", filepath.Base(root), "generation-1"}
	registration := seccheck.Registration{Namespace: target.ProducerID, InstanceID: target.InstanceID, Generation: target.Generation, SandboxID: container, ContainerID: container, PeerUID: 0}
	socket := filepath.Join(root, "events.sock")
	trace, err := seccheck.TraceConfig(socket)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON("trace.json", trace)
	writeJSON("config.json", map[string]any{
		"ociVersion": "1.0.2", "root": map[string]any{"path": rootfs, "readonly": false},
		"process": map[string]any{"terminal": false, "user": map[string]any{"uid": 0, "gid": 0}, "args": []string{"/bin/sleep", "120"}, "env": []string{"PATH=/bin:/usr/bin"}, "cwd": "/"},
		"mounts":  []map[string]any{{"destination": "/proc", "type": "proc", "source": "proc"}},
		"linux":   map[string]any{"namespaces": []map[string]string{{"type": "pid"}, {"type": "mount"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}}},
	})
	type sample struct {
		Registration     seccheck.Registration `json:"registration"`
		ConnectionID     string                `json:"connection_id"`
		Sequence         uint64                `json:"sequence"`
		Kind             string                `json:"kind"`
		Reason           string                `json:"reason,omitempty"`
		TransportPeerPID int32                 `json:"transport_peer_pid"`
		Header           *seccheck.Header      `json:"header,omitempty"`
		PacketSHA256     string                `json:"packet_sha256,omitempty"`
		Context          json.RawMessage       `json:"context_data,omitempty"`
		Identity         seccheck.Identity     `json:"identity"`
		DroppedDelta     *uint64               `json:"dropped_delta,omitempty"`
	}
	var mu sync.Mutex
	var samples []sample
	var probeRecords []seccheck.Record
	contexts := []*wire.ContextData{}
	ready := make(chan struct{})
	receiverCtx, stopReceiver := context.WithCancel(context.Background())
	done := make(chan error, 1)
	receiver := seccheck.Receiver{SocketPath: socket, Registration: registration, Ready: func() error { close(ready); return nil }, Sink: func(_ context.Context, r seccheck.Record) error {
		mu.Lock()
		defer mu.Unlock()
		if len(samples) >= 16384 {
			return fmt.Errorf("acceptance identity sample bound exceeded")
		}
		s := sample{Registration: r.Registration, ConnectionID: r.ConnectionID, Sequence: r.Sequence, Kind: r.Kind, Reason: r.Reason, TransportPeerPID: r.PeerPID, Identity: r.Identity, DroppedDelta: r.DroppedDelta}
		if r.Packet != nil {
			h := r.Packet.Header
			s.Header = &h
			s.PacketSHA256 = r.Packet.SHA256
			if c := r.Packet.Context; c != nil {
				id := &wire.ContextData{TimeNs: c.TimeNs, ThreadId: c.ThreadId, ThreadStartTimeNs: c.ThreadStartTimeNs, ThreadGroupId: c.ThreadGroupId, ThreadGroupStartTimeNs: c.ThreadGroupStartTimeNs, ContainerId: c.ContainerId, ParentThreadGroupId: c.ParentThreadGroupId, IsExecSession: c.IsExecSession}
				raw, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(id)
				if err != nil {
					return err
				}
				s.Context = raw
				contexts = append(contexts, id)
			}
		}
		samples = append(samples, s)
		if os.Getenv("AGENTPROV_TEST_RUNSC_GATE") != "" || os.Getenv("AGENTPROV_TEST_RUNSC_CONTROLLED_BINARY") != "" {
			probeRecords = append(probeRecords, r)
		}
		return nil
	}}
	go func() { done <- receiver.Serve(receiverCtx) }()
	defer func() {
		stopReceiver()
		if err := <-done; err != nil && err != context.Canceled {
			t.Error(err)
		}
		mu.Lock()
		defer mu.Unlock()
		writeJSON("sentry-identity-records.json", samples)
	}()
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatalf("receiver failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("receiver startup timed out")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	launch := exec.CommandContext(ctx, binary, "--root="+state, "--platform=systrap", "--network=none", "--pod-init-config="+filepath.Join(root, "trace.json"), "run", "--bundle="+root, container)
	launch.WaitDelay = time.Second
	launchLog, err := os.OpenFile(filepath.Join(root, "runtime-launch.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer launchLog.Close()
	launch.Stdout, launch.Stderr = launchLog, launchLog
	if err := launch.Start(); err != nil {
		t.Fatal(err)
	}
	launchDone := make(chan error, 1)
	go func() { launchDone <- launch.Wait() }()
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if raw, err := exec.CommandContext(cleanup, binary, "--root="+state, "delete", "--force", container).CombinedOutput(); err != nil {
			t.Errorf("delete disposable container: %s %v", raw, err)
		}
		select {
		case <-launchDone:
		case <-cleanup.Done():
			_ = launch.Process.Kill()
			<-launchDone
			t.Error("runtime transport required forced cleanup")
		}
	}()
	var stateRaw []byte
	var current struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		stateRaw, err = exec.CommandContext(ctx, binary, "--root="+state, "state", container).Output()
		if err == nil && json.Unmarshal(stateRaw, &current) == nil && current.Status == "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if current.Status != "running" {
		t.Fatalf("container did not start: %s %v", stateRaw, err)
	}
	writeJSON("runtime-state.json", json.RawMessage(stateRaw))
	lifecycle, err := readRunscLifecycle(state, container)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON("runtime-lifecycle.json", lifecycle)
	s := Runsc{Binding: Binding{Target: target, Mode: "runsc", ContainerID: container, StateCreated: lifecycle.CreatedAt}, Config: RunscConfig{
		Binary: binary, Root: state, ContainerID: container, StateCreated: lifecycle.CreatedAt, RuntimeRelease: seccheck.RuntimeRelease, Workdir: "/", AllowUncorrelated: true}, StateDir: root}
	r := testRequest()
	r.Target = target
	r.Command.Command = []string{"/bin/true"}
	stale := s
	stale.Config.StateCreated = "2000-01-01T00:00:00Z"
	stale.Binding.StateCreated = stale.Config.StateCreated
	if err := stale.Admit(ctx, r); err == nil || !strings.Contains(err.Error(), "lifecycle") {
		t.Fatalf("accepted a replaced container lifecycle: %v", err)
	}
	result, err := s.Run(ctx, r, nil)
	writeJSON("execution-success.json", result)
	if err != nil || result.State != "succeeded" || result.SentryPID <= 0 {
		t.Fatalf("runsc success: %+v %v", result, err)
	}
	observed := false
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, c := range contexts {
			if c.ThreadGroupId == result.SentryPID && c.ThreadGroupStartTimeNs > 0 && c.IsExecSession && c.ContainerId == container {
				observed = true
				break
			}
		}
		mu.Unlock()
		if observed {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !observed {
		t.Error("missing raw exec-session PID/birth sample; inspect identity artifacts")
	}
	if helper := os.Getenv("AGENTPROV_TEST_RUNSC_GATE"); helper != "" {
		probeControlledGate(t, ctx, s, root, helper, func() []seccheck.Record {
			mu.Lock()
			defer mu.Unlock()
			return append([]seccheck.Record(nil), probeRecords...)
		})
	}
	if executable := os.Getenv("AGENTPROV_TEST_RUNSC_CONTROLLED_BINARY"); executable != "" {
		probeGatedAdapter(t, ctx, s, root, rootfs, executable, func() []seccheck.Record {
			mu.Lock()
			defer mu.Unlock()
			return append([]seccheck.Record(nil), probeRecords...)
		})
	}
	r.OperationID, r.AttemptID = "cancel-operation", "cancel-attempt"
	r.Command.Command = []string{"/bin/sleep", "30"}
	cancelCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	var controlBirth int64
	var controlPID int32
	cancelled, cancelErr := s.Run(cancelCtx, r, func(e Execution) error {
		defer cancelExec()
		// The runtime control plane exposes exact nanosecond birth time. Retain
		// only identity fields; the full procfs dump also contains environment.
		raw, err := s.control(ctx, "--root="+state, "trace", "procfs", container)
		if err != nil {
			return fmt.Errorf("probe runtime birth identity: %w", err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var p struct {
				Start  int64 `json:"clone_ts"`
				Status struct {
					PID int32 `json:"pid"`
				} `json:"status"`
			}
			if err := json.Unmarshal([]byte(line), &p); err != nil {
				return err
			}
			if p.Status.PID == e.SentryPID {
				controlPID, controlBirth = p.Status.PID, p.Start
			}
		}
		if controlBirth <= 0 {
			return fmt.Errorf("runtime process birth identity missing")
		}
		writeJSON("runtime-process-birth.json", struct {
			PID   int32  `json:"sentry_pid"`
			Birth int64  `json:"start_time_ns,string"`
			Basis string `json:"basis"`
		}{controlPID, controlBirth, "runsc_trace_procfs"})
		return nil
	})
	writeJSON("execution-cancelled.json", cancelled)
	if cancelErr == nil || cancelled.State != "unknown" || cancelled.ExitCode != nil {
		t.Fatalf("cancelled runtime result: %+v %v", cancelled, cancelErr)
	}
	matchedBirth := false
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, c := range contexts {
			if c.ThreadGroupId == controlPID && c.ThreadGroupStartTimeNs == controlBirth && c.IsExecSession && c.ContainerId == container {
				matchedBirth = controlBirth > 0
				break
			}
		}
		mu.Unlock()
		if matchedBirth {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !matchedBirth {
		t.Error("runtime control birth did not match exact SecCheck process identity")
	}
	writeJSON("acceptance-boundary.json", map[string]any{"schema_version": Schema, "target": target, "runtime_release": seccheck.RuntimeRelease,
		"operation_receipts_observed": true, "matching_pid_birth_sample_observed": observed, "control_plane_birth_matches_sentry": matchedBirth,
		"shared_call_identity": "pending_controlled_start_gate", "per_command_event_association": "pending", "capture_completion": "incomplete"})
}

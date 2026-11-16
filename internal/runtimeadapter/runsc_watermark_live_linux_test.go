//go:build linux

package runtimeadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestRunscLiveCommandCapture(t *testing.T) {
	binary, rootfs, executable, out := os.Getenv("AGENTPROV_TEST_RUNSC"), os.Getenv("AGENTPROV_TEST_GVISOR_ROOTFS"), os.Getenv("AGENTPROV_TEST_RUNSC_CONTROLLED_BINARY"), os.Getenv("AGENTPROV_TEST_RUNTIME_ADAPTER_OUTPUT")
	if binary == "" || rootfs == "" || executable == "" || out == "" {
		t.Skip("set pinned runsc, rootfs, controlled binary and output")
	}
	if os.Geteuid() != 0 {
		t.Fatal("live runtime capture requires root")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrustedPath(out, true); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(out, "capture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("command capture evidence:", root)
	write := func(name string, value any) {
		t.Helper()
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(raw); err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	paths, err := store.Init(filepath.Join(root, "receiver"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	container := "agentprov-capture-test"
	target := Target{"acceptance", filepath.Base(root), "generation-1"}
	receiver := seccheck.Target{RunID: "native-container", SocketPath: filepath.Join(root, "events.sock"), Registration: seccheck.Registration{
		Namespace: target.ProducerID, InstanceID: target.InstanceID, Generation: target.Generation, SandboxID: container, ContainerID: container}}
	config := seccheck.CollectionConfig{SchemaVersion: seccheck.CollectionConfigSchema, RuntimeRelease: seccheck.RuntimeRelease, Targets: []seccheck.Target{receiver}}
	write("receiver-config.json", config)
	trace, err := seccheck.TraceConfig(receiver.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	write("trace.json", trace)
	write("config.json", map[string]any{"ociVersion": "1.0.2", "root": map[string]any{"path": rootfs, "readonly": false},
		"process": map[string]any{"terminal": false, "user": map[string]any{"uid": 0, "gid": 0}, "args": []string{"/bin/sleep", "300"}, "env": []string{"PATH=/bin:/usr/bin"}, "cwd": "/"},
		"mounts":  []map[string]any{{"destination": "/proc", "type": "proc", "source": "proc"}},
		"linux":   map[string]any{"namespaces": []map[string]string{{"type": "pid"}, {"type": "mount"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}}}})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	var mu sync.Mutex
	var latest telemetry.SecCheckCollectStatus
	collectorCtx, stopCollector := context.WithCancel(ctx)
	collectorDone := make(chan error, 1)
	go func() {
		collectorDone <- telemetry.CollectSecCheck(collectorCtx, db, paths, config, telemetry.SecCheckCollectOptions{StatusInterval: 100 * time.Millisecond,
			Stream: telemetry.NativeStreamOptions{FlushInterval: 100 * time.Millisecond, BatchEvents: 64}}, func(s telemetry.SecCheckCollectStatus) error { mu.Lock(); latest = s; mu.Unlock(); return nil })
	}()
	defer func() {
		stopCollector()
		if err := <-collectorDone; err != nil {
			t.Error(err)
		}
		mu.Lock()
		defer mu.Unlock()
		write("receiver-final.json", latest)
	}()
	for deadline := time.Now().Add(5 * time.Second); ; {
		mu.Lock()
		listening := latest.State == "listening"
		mu.Unlock()
		if listening {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("receiver did not listen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	log, err := os.Create(filepath.Join(root, "runsc.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	launch := exec.CommandContext(ctx, binary, "--root="+state, "--platform=systrap", "--network=none", "--pod-init-config="+filepath.Join(root, "trace.json"), "run", "--bundle="+root, container)
	launch.Stdout, launch.Stderr = log, log
	launch.WaitDelay = time.Second
	if err := launch.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- launch.Wait() }()
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := exec.CommandContext(cleanup, binary, "--root="+state, "delete", "--force", container).Run(); err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-cleanup.Done():
			launch.Process.Kill()
			<-done
			t.Error("runtime cleanup timed out")
		}
	}()
	var lifecycle runscLifecycle
	for deadline := time.Now().Add(10 * time.Second); ; {
		lifecycle, err = readRunscLifecycle(state, container)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	s := Runsc{Binding: Binding{Target: target, Mode: "runsc", ContainerID: container, StateCreated: lifecycle.CreatedAt}, StateDir: root, GateBinary: executable,
		Config: RunscConfig{Binary: binary, Root: state, ContainerID: container, StateCreated: lifecycle.CreatedAt, RuntimeRelease: seccheck.RuntimeRelease, Workdir: "/", AllowUncorrelated: true}, Options: record.Options{AllowShell: true}}
	// The trace sink connects during container creation, before OCI state
	// becomes running. Wait for the actual execution entry to be available.
	for deadline := time.Now().Add(20 * time.Second); ; {
		raw, probeErr := s.control(ctx, "--root="+state, "state", container)
		if probeErr == nil && s.validateState(raw) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("runtime did not reach running state")
		}
		time.Sleep(50 * time.Millisecond)
	}
	capture := SecCheck{Target: target, Receiver: receiver, ObserveProcesses: s.ObserveProcesses, Barrier: s.Barrier,
		ReadStatus: func(context.Context) (telemetry.SecCheckCollectStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			return latest, nil
		},
		ReadEvents: func(ctx context.Context, connection string, first uint64, count int) ([]telemetry.EventRecord, error) {
			return telemetry.ReadSecCheckSequence(ctx, db, receiver.RunID, receiver.Registration, connection, first, count)
		}}
	for i, argv := range [][]string{{"/bin/true"}, {"/bin/sh", "-c", "(/bin/sleep .05; /bin/true) & wait"}, {"/bin/sh", "-c", "exit 7"}} {
		var start CapturePoint
		for deadline := time.Now().Add(5 * time.Second); ; {
			start, err = capture.Probe(ctx, target)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		r := testRequest()
		r.Target = target
		r.OperationID = fmt.Sprintf("command-%d", i)
		r.AttemptID = r.OperationID + "-attempt"
		r.Command.Command = argv
		execution, runErr := s.Run(ctx, r, func(e Execution) error { write(fmt.Sprintf("command-%d-checkpoint.json", i), e); return nil })
		write(fmt.Sprintf("command-%d-execution.json", i), execution)
		if i < 2 && runErr != nil {
			t.Fatal(runErr)
		}
		finishCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		result := capture.FinishCommand(finishCtx, r, execution, start)
		stop()
		write(fmt.Sprintf("command-%d-capture.json", i), result)
		if result.Evidence != nil {
			write(fmt.Sprintf("command-%d-evidence.json", i), result.Evidence)
		}
		if result.State != "sealed" || result.Command == nil || result.Evidence == nil {
			t.Fatalf("real command capture did not seal: %+v", result)
		}
		want := int32(0)
		if i == 2 {
			want = 7 << 8
		}
		if result.Command.RootWaitStatus != want {
			t.Fatalf("native exit status: %d", result.Command.RootWaitStatus)
		}
		if i == 1 && result.Command.ProcessCount < 2 {
			t.Fatal("background child missing from command scope")
		}
	}
}

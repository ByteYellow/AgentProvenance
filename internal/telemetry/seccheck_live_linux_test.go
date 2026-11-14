//go:build linux && (amd64 || arm64)

package telemetry_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"golang.org/x/sys/unix"
)

func TestSecCheckLivePersistence(t *testing.T) {
	runsc, rootfs, workload := os.Getenv("AGENTPROV_TEST_RUNSC"), os.Getenv("AGENTPROV_TEST_GVISOR_ROOTFS"), os.Getenv("AGENTPROV_TEST_SECCHECK_WORKLOAD_BINARY")
	if runsc == "" || rootfs == "" || workload == "" {
		t.Skip("set runsc, rootfs and the internal/seccheck test workload binary")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated runsc acceptance requires root")
	}
	version, err := exec.Command(runsc, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), seccheck.RuntimeRelease) {
		t.Fatalf("runtime pin: %s %v", version, err)
	}
	root := os.Getenv("AGENTPROV_TEST_SECCHECK_OUTPUT")
	if root == "" {
		root = t.TempDir()
	}
	paths, err := store.Init(filepath.Join(root, "source"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stream, err := telemetry.NewSecCheckStream(db, paths, telemetry.NativeStreamOptions{BatchEvents: 8, FlushInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() { workerDone <- stream.Run(workerCtx, func(err error) { t.Errorf("spool worker: %v", err) }) }()
	workerStopped := false
	defer func() {
		if !workerStopped {
			stopWorker()
			<-workerDone
		}
	}()
	writeJSON := func(path string, value any) {
		t.Helper()
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	type sandbox struct {
		name         string
		cmd          *exec.Cmd
		output       []byte
		err          error
		disconnected chan struct{}
	}
	instances := []*sandbox{}
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("seccheck-persist-%d", i)
		dir, err := os.MkdirTemp("/tmp", "ap-sc-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		socket := filepath.Join(dir, "receiver.sock")
		reg := seccheck.Registration{Namespace: "live-acceptance", InstanceID: runtime.GOARCH + "-systrap", Generation: "1", SandboxID: name, ContainerID: name, PeerUID: uint32(os.Geteuid())}
		receiverCtx, stopReceiver := context.WithCancel(ctx)
		done := make(chan error, 1)
		disconnected := make(chan struct{}, 1)
		sink := stream.Sink("gvisor-persistence", reg)
		receiver := seccheck.Receiver{SocketPath: socket, Registration: reg, Sink: func(ctx context.Context, r seccheck.Record) error {
			err := sink(ctx, r)
			if err == nil && r.Reason == "disconnected" {
				select {
				case disconnected <- struct{}{}:
				default:
				}
			}
			return err
		}}
		go func() { done <- receiver.Serve(receiverCtx) }()
		t.Cleanup(func() {
			stopReceiver()
			if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("receiver: %v", err)
			}
		})
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(socket); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("receiver did not listen")
			}
			time.Sleep(5 * time.Millisecond)
		}
		state := filepath.Join(dir, "state")
		t.Cleanup(func() {
			cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if out, err := exec.CommandContext(cleanupCtx, runsc, "--root="+state, "delete", "--force", name).CombinedOutput(); err != nil {
				t.Errorf("sandbox cleanup: %s %v", out, err)
			}
			if err := unix.Unmount(filepath.Join(state, "null-netns"), 0); err != nil && err != unix.ENOENT && err != unix.EINVAL {
				t.Errorf("namespace cleanup: %v", err)
			}
		})
		config := map[string]any{
			"ociVersion": "1.0.2", "hostname": "seccheck",
			"process": map[string]any{"user": map[string]int{"uid": 0, "gid": 0}, "terminal": false, "args": []string{"/acceptance", "-test.run=^TestSecCheckLiveWorkload$", "-test.v"}, "env": []string{"PATH=/bin:/usr/bin", "AGENTPROV_SECCHECK_CHILD=1"}, "cwd": "/", "noNewPrivileges": true},
			"root":    map[string]any{"path": rootfs, "readonly": true},
			"mounts": []any{
				map[string]any{"destination": "/proc", "type": "proc", "source": "proc"},
				map[string]any{"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
				map[string]any{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "nodev", "size=16m"}},
				map[string]any{"destination": "/acceptance", "type": "bind", "source": workload, "options": []string{"bind", "ro"}},
			},
			"linux": map[string]any{"namespaces": []any{map[string]string{"type": "pid"}, map[string]string{"type": "network"}, map[string]string{"type": "ipc"}, map[string]string{"type": "uts"}, map[string]string{"type": "mount"}}},
		}
		writeJSON(filepath.Join(dir, "config.json"), config)
		points := []map[string]any{}
		fields := []string{"time", "thread_id", "task_start_time", "group_id", "thread_group_start_time", "container_id", "cwd", "process_name", "parent_thread_group_id"}
		for _, point := range []string{"container/start", "sentry/clone", "sentry/execve", "sentry/task_exit", "syscall/openat/enter", "syscall/openat/exit", "syscall/connect/enter", "syscall/connect/exit", "syscall/execve/enter", "syscall/execve/exit"} {
			points = append(points, map[string]any{"name": point, "context_fields": fields})
		}
		trace := filepath.Join(dir, "trace.json")
		writeJSON(trace, map[string]any{"trace_session": map[string]any{"name": "Default", "points": points, "sinks": []any{map[string]any{"name": "remote", "config": map[string]any{"endpoint": socket}}}}})
		cmd := exec.CommandContext(ctx, runsc, "--root="+state, "--platform=systrap", "--network=none", "--pod-init-config="+trace, "run", "--bundle="+dir, name)
		instances = append(instances, &sandbox{name: name, cmd: cmd, disconnected: disconnected})
	}
	var wg sync.WaitGroup
	for _, s := range instances {
		wg.Add(1)
		go func(s *sandbox) { defer wg.Done(); s.output, s.err = s.cmd.CombinedOutput() }(s)
	}
	wg.Wait()
	for _, s := range instances {
		if s.err != nil || !bytes.Contains(s.output, []byte("SECCHECK_OK")) {
			t.Fatalf("%s: %s %v", s.name, s.output, s.err)
		}
		select {
		case <-s.disconnected:
		case <-ctx.Done():
			t.Fatal("missing final disconnect evidence")
		}
	}
	stopWorker()
	if err := <-workerDone; err != nil {
		t.Fatal(err)
	}
	workerStopped = true
	if err := stream.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := stream.Status(ctx)
	if err != nil || status.PendingEvents != 0 || status.QueuedBytes != 0 {
		t.Fatalf("status=%+v %v", status, err)
	}
	before, err := telemetry.ListEvents(db, "gvisor-persistence", "")
	if err != nil {
		t.Fatal(err)
	}
	counts, results := map[string]int{}, map[string]map[string]int{}
	roots, files := map[string]bool{}, map[string]bool{}
	for _, e := range before {
		if e.Source != "gvisor_seccheck" || e.ToolCallID != "" || e.SessionID != "" || e.CgroupID != "" {
			t.Fatalf("wrong source/attribution: %+v", e)
		}
		if err := telemetry.ValidateStoredPayload(e.EventType, e.Payload); err != nil {
			t.Fatal(err)
		}
		var body struct {
			Outcome   string                     `json:"syscall_outcome"`
			Operation string                     `json:"operation"`
			Sentry    telemetry.SecCheckEvidence `json:"sentry"`
		}
		if err := json.Unmarshal([]byte(e.Payload), &body); err != nil {
			t.Fatal(err)
		}
		if body.Sentry.Kind == "event" && (body.Sentry.DroppedDelta == nil || *body.Sentry.DroppedDelta != 0) {
			t.Fatalf("live loss: %s", e.Payload)
		}
		name := body.Sentry.Registration.SandboxID
		counts[name]++
		if results[name] == nil {
			results[name] = map[string]int{}
		}
		resultKind := e.EventType
		if e.EventType == "syscall_result" {
			resultKind = body.Operation
		}
		results[name][resultKind+"/"+body.Outcome]++
		identity := telemetry.ProcessGraphIdentity(e)
		if e.PID == 1 {
			roots[identity.Process.ID] = true
		}
		file, path := telemetry.SecCheckFileNode(e)
		if e.EventType == "file_open" && path == "/tmp/seccheck-result" {
			files[file] = true
		}
	}
	if len(roots) != 2 || roots[""] || len(files) != 2 || files[""] {
		t.Fatalf("merged sandbox identities: roots=%v files=%v", roots, files)
	}
	for _, s := range instances {
		for _, outcome := range []string{"network_connect/success", "network_connect/failure", "network_connect/pending", "file_open/success", "file_open/failure", "execve/", "thread_exit/"} {
			if results[s.name][outcome] == 0 {
				t.Fatalf("missing %s for %s: %v", outcome, s.name, results)
			}
		}
	}
	verified, err := provenance.Verify(db, "gvisor-persistence")
	if err != nil || verified.ErrorCount != 0 || verified.WarningCount != 0 {
		t.Fatalf("verify=%+v %v", verified, err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("gvisor-persistence")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, public); err != nil {
		t.Fatal(err)
	}
	replayPaths, err := store.Init(filepath.Join(root, "receiver"))
	if err != nil {
		t.Fatal(err)
	}
	replayDB, err := store.Open(replayPaths)
	if err != nil {
		t.Fatal(err)
	}
	defer replayDB.Close()
	if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	after, err := telemetry.ListEvents(replayDB, "gvisor-persistence", "")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("signed evidence changed: %v", err)
	}
	verified, err = provenance.Verify(replayDB, "gvisor-persistence")
	if err != nil || verified.ErrorCount != 0 || verified.WarningCount != 0 {
		t.Fatalf("replay verify=%+v %v", verified, err)
	}
	writeJSON(filepath.Join(root, "events.json"), before)
	writeJSON(filepath.Join(root, "result.json"), map[string]any{"status": status, "counts": counts, "outcomes": results, "bundle": bundle, "public_key": public, "verify": verified})
	t.Logf("persisted=%v results=%v pending=%d signed_roundtrip=%d", counts, results, status.PendingEvents, len(after))
}

//go:build linux && (amd64 || arm64)

package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/sensor"
)

// Select only this test's two kernel cgroups. The payload is the sensor's actual
// output; no event identities, timestamps, or process observations are added.
type nativePrefixLiveWriter struct {
	stream  *NativeStream
	groups  map[string]bool
	marks   map[string]chan struct{}
	mu      sync.Mutex
	block   string
	entered chan struct{}
	release chan struct{}
}

func (w *nativePrefixLiveWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var event map[string]any
	if err := json.Unmarshal(data, &event); err != nil {
		return 0, err
	}
	group, _ := event["cgroup_id"].(string)
	if !w.groups[group] {
		return len(data), nil
	}
	if path, _ := event["path"].(string); w.block != "" && filepath.Base(path) == w.block {
		w.block = ""
		close(w.entered)
		<-w.release
	}
	n, err := w.stream.Write(data)
	if err == nil && event["event_type"] == "file_open" && event["mode"] == "write" {
		path, _ := event["path"].(string)
		if mark := w.marks[filepath.Base(path)]; mark != nil {
			close(mark)
			delete(w.marks, filepath.Base(path))
		}
	}
	return n, err
}

func TestLiveNativePrefixWhileSensorContinues(t *testing.T) {
	runLiveNativePrefix(t, false)
}

func TestLiveNativeBoundaryWhileSensorContinues(t *testing.T) {
	runLiveNativePrefix(t, true)
}

func runLiveNativePrefix(t *testing.T, withBoundary bool) {
	t.Helper()
	if os.Getenv("AGENTPROV_TEST_NATIVE_PREFIX") != "1" {
		t.Skip("set AGENTPROV_TEST_NATIVE_PREFIX=1 on Linux with BPF and cgroup v2 permissions")
	}
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 64})
	writer := &nativePrefixLiveWriter{stream: n, groups: map[string]bool{}, marks: map[string]chan struct{}{}}
	var releaseOnce sync.Once
	if withBoundary {
		writer.block = "prefix-0.txt"
		writer.entered, writer.release = make(chan struct{}), make(chan struct{})
		defer releaseOnce.Do(func() { close(writer.release) })
	}
	work := t.TempDir()
	commands := make([]*exec.Cmd, 2)
	marks := make([]chan struct{}, 2)
	for i := range 2 {
		group := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("agentprov-prefix-%d-%d-%d", os.Getpid(), time.Now().UnixNano(), i))
		if err := os.Mkdir(group, 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(group)
		if err != nil {
			os.Remove(group)
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close(); os.Remove(group) })
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		groupID := strconv.FormatUint(info.Sys().(*syscall.Stat_t).Ino, 10)
		writer.groups[groupID] = true
		_, err = correlation.RecordBinding(db, correlation.Binding{RunID: fmt.Sprintf("run-prefix-%d", i),
			SessionID: fmt.Sprintf("session-prefix-%d", i), ToolCallID: fmt.Sprintf("tool-prefix-%d", i),
			ProcessID: fmt.Sprintf("process-prefix-%d", i), CgroupID: groupID,
			StartedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), BindingSource: correlation.BindingSourceK8sCgroup})
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("prefix-%d.txt", i)
		marks[i] = make(chan struct{})
		writer.marks[name] = marks[i]
		commands[i] = exec.Command("/bin/sh", "-c", "printf 'captured by native sensor\\n' > "+name)
		commands[i].Dir = work
		commands[i].SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(file.Fd())}
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	var checkpointer *sensor.Checkpointer
	if withBoundary {
		checkpointer = sensor.NewCheckpointer()
	}
	go func() {
		done <- sensor.RunWithOptions(writer, sensor.Options{Context: ctx, Diagnostics: io.Discard,
			Checkpointer: checkpointer, AppArmorState: withBoundary, SeccompState: withBoundary,
			OnReady: func() { close(ready) }})
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		cancel()
		select {
		case err := <-done:
			stopped = true
			if err != nil {
				t.Errorf("sensor shutdown: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("sensor shutdown timed out")
		}
	}
	t.Cleanup(stop)
	select {
	case <-ready:
	case err := <-done:
		stopped = true
		cancel()
		t.Fatalf("sensor exited before readiness: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("sensor readiness timed out")
	}
	run := func(i int) {
		t.Helper()
		if output, err := commands[i].CombinedOutput(); err != nil {
			t.Fatalf("fixture %d: %s %v", i, output, err)
		}
		body, err := os.ReadFile(filepath.Join(work, fmt.Sprintf("prefix-%d.txt", i)))
		if err != nil || string(body) != "captured by native sensor\n" {
			t.Fatalf("fixture %d file output: %q %v", i, body, err)
		}
		if withBoundary {
			return
		}
		select {
		case <-marks[i]:
		case <-time.After(5 * time.Second):
			t.Fatalf("fixture %d write-mode file_open did not reach the native spool", i)
		}
	}
	run(0)
	var prefix NativePrefix
	var err error
	if withBoundary {
		select {
		case <-writer.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("first event did not reach the blocked writer")
		}
		blockedCtx, cancelBlocked := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := checkpointer.Checkpoint(blockedCtx, func(sensor.CaptureBoundary) error {
			t.Error("checkpoint overtook a blocked event writer")
			return nil
		})
		cancelBlocked()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked decoder checkpoint: %v", err)
		}
		releaseOnce.Do(func() { close(writer.release) })
		boundaryCtx, cancelBoundary := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelBoundary()
		boundary, checkpointErr := checkpointer.Checkpoint(boundaryCtx, func(sensor.CaptureBoundary) error {
			prefix, err = n.SnapshotPrefix(boundaryCtx)
			return err
		})
		err = checkpointErr
		if err != nil || boundary.KernelTimeNS == 0 || boundary.DecodedRecords == 0 || boundary.Sequence != 2 {
			t.Fatalf("live sensor boundary=%+v error=%v", boundary, err)
		}
		select {
		case <-marks[0]:
		default:
			t.Fatal("kernel checkpoint overtook the earlier file write")
		}
		t.Logf("kernel boundary: %+v", boundary)
	} else {
		prefix, err = n.SnapshotPrefix(context.Background())
	}
	if err != nil || prefix.Sequence == 0 || len(prefix.Batches) == 0 {
		t.Fatalf("live prefix=%+v error=%v", prefix, err)
	}
	run(1)
	if withBoundary {
		if _, err := checkpointer.Checkpoint(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	progress, err := n.DrainPrefix(context.Background(), prefix)
	if err != nil || progress.State != "settled" || progress.Ingested == 0 || progress.Failed != 0 || progress.Dropped != 0 {
		t.Fatalf("live prefix progress=%+v error=%v", progress, err)
	}
	var first, later int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-prefix-0' AND event_type='file_write'`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-prefix-1'`).Scan(&later); err != nil || first == 0 || later != 0 {
		t.Fatalf("live scope prefix crossed boundary: first=%d later=%d error=%v", first, later, err)
	}
	select {
	case err := <-done:
		stopped = true
		t.Fatalf("sensor stopped during prefix drain: %v", err)
	default:
	}
	t.Logf("sensor remained active; collector=%s sequence=%d prefix_batches=%d ingested=%d later_run_saved=%d",
		prefix.CollectorID, prefix.Sequence, len(prefix.Batches), progress.Ingested, later)
	stop()
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := n.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-prefix-1' AND event_type='file_write'`).Scan(&later); err != nil || later == 0 {
		t.Fatalf("later evidence lost: %d %v", later, err)
	}
}
